package analyze

import (
	"fmt"
	"strings"

	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

// seccomp, seccompFilters, NoNewPrivs

/**
 * rules:
 * 1. NoNewPrivs == false 						=> Info/MediumRisk (may involve compositing later)
 * 2. SeccompMode == 0 (No seccomp) 			=> HighRisk
 * 3. SeccompMode == 1 (strict seccomp) 		=> Info (may be too strict)
 * 4. SeccompMode == 2 && Seccomp_Filters == 0 	=> HighRisk (abnormal, may not be considered as risk?)
 */

func newSeccompSignal(thread *target.Thread, mountPoints []string, riskLevel int, title, summary, recommendation string) *model.Signal {
	return &model.Signal{
		Finding: model.Finding{
			Category:  "seccomp",
			RiskLevel: riskLevel,
			Title:     title,
			Summary:   summary,
			Evidence: []string{
				fmt.Sprintf("tid=%d, tgid=%d, comm=%q, main_thread=%t", thread.Tid, thread.Tgid, strings.TrimSpace(thread.Comm), thread.IsMainThread),
				fmt.Sprintf("NoNewPrivs=%t, SeccompMode=%d, SeccompFilters=%d", thread.NoNewPrivs, thread.SeccompMode, thread.SeccompFilters),
				fmt.Sprintf("userns=%s, mntns=%s, pidns=%s", formatNSRef(thread.UserNS), formatNSRef(thread.MntNS), formatNSRef(thread.PIDNS)),
			},
			RelativeThreads: []*target.Thread{thread},
			MountPoint:      mountPoints,
			Recommendation:  recommendation,
		},
	}
}

// checkNoNewPrivs checks rule 1: NoNewPrivs is shut down
// This is mostly a composition signal rather than a direct boundary break
func checkNoNewPrivs(thread *target.Thread, mountPoints []string) *model.Signal {
	if thread.NoNewPrivs {
		return nil
	}
	return newSeccompSignal(
		thread,
		mountPoints,
		Info,
		"Thread does not enable no_new_privs",
		fmt.Sprintf("Thread %d does not enable no_new_privs, so later execve paths can still participate in privilege-gaining transitions and seccomp hardening depends more on surrounding runtime behavior.", thread.Tid),
		"Enable no_new_privs before installing seccomp filters or running helper paths unless a reviewed privilege transition explicitly requires it.",
	)
}

// switchSeccompMode is a distributor of seccomp mode handlers
func switchSeccompMode(thread *target.Thread, mountPoints []string) *model.Signal {
	switch thread.SeccompMode {
	case 0:
		return checkSeccompModeShutDown(thread, mountPoints)
	case 1:
		return checkSeccompModeStrict(thread, mountPoints)
	default:
		return nil
	}
}

// checkSeccompModeShutDown checks rule 2: seccompMode shut down
func checkSeccompModeShutDown(thread *target.Thread, mountPoints []string) *model.Signal {
	return newSeccompSignal(
		thread,
		mountPoints,
		HighRisk,
		"Thread runs without seccomp filtering",
		fmt.Sprintf("Thread %d runs without seccomp filtering, so its syscall surface is limited only by namespaces, capabilities, LSM policy, and the kernel attack surface they still expose.", thread.Tid),
		"Keep seccomp enabled in filter mode for ordinary application containers and reduce the allowed syscall set to the workload's reviewed needs.",
	)
}

// checkSeccompModeStrict checks rule 3: seccomp is in strict mode
func checkSeccompModeStrict(thread *target.Thread, mountPoints []string) *model.Signal {
	return newSeccompSignal(
		thread,
		mountPoints,
		Info,
		"Thread uses strict seccomp mode",
		fmt.Sprintf("Thread %d uses strict seccomp mode, which is a very restrictive syscall policy. This is usually intentional hardening, but it is unusual enough to verify rather than assume a normal filter-profile deployment.", thread.Tid),
		"Keep strict mode only for workloads designed for that syscall model; otherwise use filter mode with an explicit reviewed seccomp profile.",
	)
}

// checkSeccompModeOnWithoutFilters checks rule 4: seccompMode is at
// filter mode (seccompMode == 2) but no filters
func checkSeccompModeOnWithoutFilters(thread *target.Thread, mountPoints []string) *model.Signal {
	if thread.SeccompMode != 2 || thread.SeccompFilters != 0 {
		return nil
	}
	return newSeccompSignal(
		thread,
		mountPoints,
		HighRisk,
		"Thread reports seccomp filter mode without attached filters",
		fmt.Sprintf("Thread %d reports seccomp filter mode but zero attached filters, which is abnormal and suggests incomplete hardening or inconsistent status data.", thread.Tid),
		"Verify that the runtime actually installed seccomp filters and investigate the collector or kernel status view if this state was not expected.",
	)
}

// AnalyzeSeccomp is the entry point of seccomp analysis
func (r *Rule) AnalyzeSeccomp() {
	for _, threadSnapshot := range r.Snapshot.Threads {
		thread := target.Thread(threadSnapshot)
		mountPoints := r.mountPointsForThread(&thread)

		r.Signals = appendSignalIfNonNil(r.Signals, checkNoNewPrivs(&thread, mountPoints))
		r.Signals = appendSignalIfNonNil(r.Signals, switchSeccompMode(&thread, mountPoints))
		r.Signals = appendSignalIfNonNil(r.Signals, checkSeccompModeOnWithoutFilters(&thread, mountPoints))
	}
}
