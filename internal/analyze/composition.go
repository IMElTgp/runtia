package analyze

import (
	"fmt"
	"slices"
	"strings"

	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

// signalThread returns the first thread of signal.RelativeThreads
// maybe the design of signal.RelativeThreads is not proper; will
// signal.RelativeThread (of type *target.Thread) be better?
func signalThread(signal model.Signal) *target.Thread {
	if len(signal.RelativeThreads) == 0 {
		return nil
	}
	return signal.RelativeThreads[0]
}

// signalMentionsThread checks if a signal is related to given thread
func signalMentionsThread(signal model.Signal, tid int) bool {
	for _, thread := range signal.RelativeThreads {
		if thread != nil && thread.Tid == tid {
			return true
		}
	}
	return false
}

// capabilitySetLabelFromFinding returns the capability name that a
// signal claimed
func capabilitySetLabelFromFinding(finding *model.Finding) string {
	title := strings.TrimPrefix(finding.Title, "Thread has ")
	_, rest, found := strings.Cut(title, " in its ")
	if !found {
		return ""
	}
	return strings.TrimSuffix(rest, " capability set")
}

// isCapabilitySignal checks if a signal contains given capability
// where `sets` contains at least one of eff, prm, inh, amb, and bnd
func isCapabilitySignal(signal model.Signal, capName string, sets ...string) bool {
	if signal.Category != "capabilities" {
		return false
	}
	if ParseCapabilityNameFromFinding(&signal.Finding) != capName {
		return false
	}
	if len(sets) == 0 {
		return true
	}
	return slices.Contains(sets, capabilitySetLabelFromFinding(&signal.Finding))
}

// isAnyCapabilitySignal checks if a signal contains any capability in
// capNames within the given capability sets.
func isAnyCapabilitySignal(signal model.Signal, capNames []string, sets ...string) bool {
	for _, capName := range capNames {
		if isCapabilitySignal(signal, capName, sets...) {
			return true
		}
	}
	return false
}

// isMountSignalForThread checks if a mount signal is related to the
// given thread.
func isMountSignalForThread(signal model.Signal, thread *target.Thread) bool {
	return signal.Category == "mount" && thread != nil && signalMentionsThread(signal, thread.Tid)
}

// isHostPIDNamespaceSignalForThread checks if a host PID namespace
// signal is related to the given thread.
func isHostPIDNamespaceSignalForThread(signal model.Signal, thread *target.Thread) bool {
	return signal.Category == "namespace" &&
		signal.Title == "Thread shares the host PID namespace" &&
		thread != nil &&
		signalMentionsThread(signal, thread.Tid)
}

// isMountNamespaceDeviationSignalForThread checks if a mount namespace
// deviation signal is related to the given thread.
func isMountNamespaceDeviationSignalForThread(signal model.Signal, thread *target.Thread) bool {
	return signal.Category == "namespace" &&
		signal.Title == "Thread uses a different mount namespace than its main thread" &&
		thread != nil &&
		signalMentionsThread(signal, thread.Tid)
}

// isNonPrivateMountSignalForThread checks if a non-private mount
// propagation signal is related to the given thread.
func isNonPrivateMountSignalForThread(signal model.Signal, thread *target.Thread) bool {
	return isMountSignalForThread(signal, thread) &&
		signal.Title == "Mount point with non-private status in mount tree"
}

// isWritableHostOrSensitiveMountForThread checks if a writable host or
// sensitive runtime mount signal is related to the given thread.
func isWritableHostOrSensitiveMountForThread(signal model.Signal, thread *target.Thread) bool {
	if !isMountSignalForThread(signal, thread) || len(signal.MountPoint) == 0 {
		return false
	}
	switch signal.Title {
	case "Host filesystem view /host is writable",
		"Host filesystem view /rootfs is writable",
		"Sensitive runtime path /etc is writable",
		"Sensitive runtime path /run is writable",
		"Sensitive runtime path /var/run is writable":
		return true
	default:
		return false
	}
}

// isUnconfinedSeccompSignal checks if a signal reports that seccomp is
// not enabled for a thread.
func isUnconfinedSeccompSignal(signal model.Signal) bool {
	return signal.Category == "seccomp" && signal.Title == "Thread runs without seccomp filtering"
}

// isNoNewPrivsDisabledSignal checks if a signal reports that
// no_new_privs is not enabled for a thread.
func isNoNewPrivsDisabledSignal(signal model.Signal) bool {
	return signal.Category == "seccomp" && signal.Title == "Thread does not enable no_new_privs"
}

// uniqueMountPointsFromSignals collects unique mount points from the
// given signal indexes and returns them in sorted order.
func uniqueMountPointsFromSignals(signals []model.Signal, indexes []int) []string {
	seen := make(map[string]struct{})
	mountPoints := make([]string, 0)
	for _, idx := range indexes {
		for _, mountPoint := range signals[idx].MountPoint {
			if mountPoint == "" {
				continue
			}
			if _, ok := seen[mountPoint]; ok {
				continue
			}
			seen[mountPoint] = struct{}{}
			mountPoints = append(mountPoints, mountPoint)
		}
	}
	slices.Sort(mountPoints)
	return mountPoints
}

// capabilityNamesFromSignals collects unique capability names from the
// given signal indexes and returns them in sorted order.
func capabilityNamesFromSignals(signals []model.Signal, indexes []int) []string {
	seen := make(map[string]struct{})
	names := make([]string, 0, len(indexes))
	for _, idx := range indexes {
		name := ParseCapabilityNameFromFinding(&signals[idx].Finding)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// markCovered marks the given signal indexes as covered when they are
// within the current rule's signal range.
func (r *Rule) markCovered(indexes ...int) {
	for _, idx := range indexes {
		if idx < 0 || idx >= len(r.Signals) {
			continue
		}
		r.Signals[idx].Covered = true
	}
}

// appendComposition marks the related source signals as covered and
// appends the synthesized composition signal.
func (r *Rule) appendComposition(signal model.Signal, coveredIndexes ...int) {
	r.markCovered(coveredIndexes...)
	r.Signals = append(r.Signals, signal)
}

// newCompositionSignal builds a composition-category signal from the
// provided risk, description, scope, and evidence fields.
func newCompositionSignal(
	riskLevel int,
	title, summary, recommendation string,
	thread *target.Thread,
	relativeNS *target.NSRef,
	mountPoints []string,
	evidence []string,
) model.Signal {
	var relatedThreads []*target.Thread
	if thread != nil {
		relatedThreads = []*target.Thread{thread}
	}

	return model.Signal{
		Finding: model.Finding{
			Category:        "composition",
			RiskLevel:       riskLevel,
			Title:           title,
			Summary:         summary,
			Evidence:        evidence,
			RelativeThreads: relatedThreads,
			RelativeNS:      relativeNS,
			MountPoint:      mountPoints,
			Recommendation:  recommendation,
		},
	}
}

// analyzeCompositionCAPSysPtraceHostPIDNamespace finds threads that
// combine CAP_SYS_PTRACE with the host PID namespace.
func (r *Rule) analyzeCompositionCAPSysPtraceHostPIDNamespace() {
	for capIdx := range r.Signals {
		capSignal := r.Signals[capIdx]
		if !isCapabilitySignal(capSignal, "CAP_SYS_PTRACE", "effective", "permitted") {
			continue
		}

		thread := signalThread(capSignal)
		if thread == nil {
			continue
		}

		nsIdx := -1
		for i := range r.Signals {
			if isHostPIDNamespaceSignalForThread(r.Signals[i], thread) {
				nsIdx = i
				break
			}
		}
		if nsIdx == -1 {
			continue
		}

		pidNS := thread.PIDNS
		signal := newCompositionSignal(
			Fatal,
			"CAP_SYS_PTRACE combined with host PID namespace",
			fmt.Sprintf("Thread %d can trace or influence processes while sharing the host PID namespace, so host or cross-workload process boundaries are significantly weakened.", thread.Tid),
			"Drop CAP_SYS_PTRACE unless the workload is a tightly reviewed debugger, and keep the workload in a private PID namespace.",
			thread,
			&pidNS,
			nil,
			[]string{
				capSignal.Title,
				r.Signals[nsIdx].Title,
				fmt.Sprintf("tid=%d, tgid=%d, pidns=%s", thread.Tid, thread.Tgid, formatNSRef(thread.PIDNS)),
			},
		)
		r.appendComposition(signal, capIdx, nsIdx)
	}
}

// analyzeCompositionCAPSysAdminNonPrivateMountPropagation finds
// threads that combine CAP_SYS_ADMIN with non-private mount
// propagation.
func (r *Rule) analyzeCompositionCAPSysAdminNonPrivateMountPropagation() {
	for capIdx := range r.Signals {
		capSignal := r.Signals[capIdx]
		if !isCapabilitySignal(capSignal, "CAP_SYS_ADMIN", "effective", "permitted") {
			continue
		}

		thread := signalThread(capSignal)
		if thread == nil {
			continue
		}

		mountIndexes := make([]int, 0)
		for i := range r.Signals {
			if isNonPrivateMountSignalForThread(r.Signals[i], thread) {
				mountIndexes = append(mountIndexes, i)
			}
		}
		if len(mountIndexes) == 0 {
			continue
		}

		mntNS := thread.MntNS
		mountPoints := uniqueMountPointsFromSignals(r.Signals, mountIndexes)
		evidence := []string{
			capSignal.Title,
			fmt.Sprintf("Thread mount namespace=%s", formatNSRef(thread.MntNS)),
			fmt.Sprintf("Non-private mount points=%s", strings.Join(mountPoints, ", ")),
		}
		for _, idx := range mountIndexes {
			evidence = append(evidence, r.Signals[idx].Title)
		}

		signal := newCompositionSignal(
			Fatal,
			"CAP_SYS_ADMIN combined with non-private mount propagation",
			fmt.Sprintf("Thread %d has CAP_SYS_ADMIN while its mount namespace exposes non-private propagation, so mount operations can interact with a weaker propagation boundary than an isolated container should have.", thread.Tid),
			"Remove CAP_SYS_ADMIN unless it is narrowly required, and make container-visible mounts private so mount propagation cannot cross the intended isolation boundary.",
			thread,
			&mntNS,
			mountPoints,
			evidence,
		)
		covered := append([]int{capIdx}, mountIndexes...)
		r.appendComposition(signal, covered...)
	}
}

// analyzeCompositionCAPDACOverrideWritableHostMount finds threads that
// combine CAP_DAC_OVERRIDE with writable host or sensitive mounts.
func (r *Rule) analyzeCompositionCAPDACOverrideWritableHostMount() {
	for capIdx := range r.Signals {
		capSignal := r.Signals[capIdx]
		if !isCapabilitySignal(capSignal, "CAP_DAC_OVERRIDE", "effective", "permitted") {
			continue
		}

		thread := signalThread(capSignal)
		if thread == nil {
			continue
		}

		mountIndexes := make([]int, 0)
		for i := range r.Signals {
			if isWritableHostOrSensitiveMountForThread(r.Signals[i], thread) {
				mountIndexes = append(mountIndexes, i)
			}
		}
		if len(mountIndexes) == 0 {
			continue
		}

		mntNS := thread.MntNS
		mountPoints := uniqueMountPointsFromSignals(r.Signals, mountIndexes)
		evidence := []string{
			capSignal.Title,
			fmt.Sprintf("Thread mount namespace=%s", formatNSRef(thread.MntNS)),
			fmt.Sprintf("Writable host/sensitive mount points=%s", strings.Join(mountPoints, ", ")),
		}
		for _, idx := range mountIndexes {
			evidence = append(evidence, r.Signals[idx].Title)
		}

		signal := newCompositionSignal(
			Fatal,
			"CAP_DAC_OVERRIDE combined with writable host or sensitive mount",
			fmt.Sprintf("Thread %d can bypass DAC permission checks while also seeing writable host or sensitive runtime paths, so file-integrity impact is stronger than either signal alone.", thread.Tid),
			"Drop CAP_DAC_OVERRIDE unless the workload has a narrow reviewed need for it, and keep host or sensitive runtime mounts read-only or absent.",
			thread,
			&mntNS,
			mountPoints,
			evidence,
		)
		covered := append([]int{capIdx}, mountIndexes...)
		r.appendComposition(signal, covered...)
	}
}

// analyzeCompositionUnconfinedSeccompHighRiskCapability finds threads
// that combine unconfined seccomp with high-risk capabilities.
func (r *Rule) analyzeCompositionUnconfinedSeccompHighRiskCapability() {
	for seccompIdx := range r.Signals {
		seccompSignal := r.Signals[seccompIdx]
		if !isUnconfinedSeccompSignal(seccompSignal) {
			continue
		}

		thread := signalThread(seccompSignal)
		if thread == nil {
			continue
		}

		capIndexes := make([]int, 0)
		highestRisk := HighRisk
		for i := range r.Signals {
			sig := r.Signals[i]
			if sig.Category != "capabilities" || !signalMentionsThread(sig, thread.Tid) || sig.RiskLevel < HighRisk {
				continue
			}
			capIndexes = append(capIndexes, i)
			if sig.RiskLevel > highestRisk {
				highestRisk = sig.RiskLevel
			}
		}
		if len(capIndexes) == 0 {
			continue
		}

		capabilityNames := capabilityNamesFromSignals(r.Signals, capIndexes)
		evidence := []string{
			seccompSignal.Title,
			fmt.Sprintf("High-risk capabilities on tid=%d: %s", thread.Tid, strings.Join(capabilityNames, ", ")),
		}
		for _, idx := range capIndexes {
			evidence = append(evidence, r.Signals[idx].Title)
		}

		signal := newCompositionSignal(
			highestRisk,
			"Unconfined seccomp combined with high-risk capability",
			fmt.Sprintf("Thread %d runs without seccomp filtering while also retaining high-risk capabilities, so both the reachable syscall surface and privileged kernel interaction surface are broader than in a hardened container.", thread.Tid),
			"Keep seccomp enabled in filter mode and remove high-risk capabilities that are not strictly required by the workload.",
			thread,
			nil,
			nil,
			evidence,
		)
		covered := append([]int{seccompIdx}, capIndexes...)
		r.appendComposition(signal, covered...)
	}
}

// analyzeCompositionNoNewPrivsDelayedPrivilegeTransitionCapability
// finds threads that keep delayed privilege-transition capabilities
// while no_new_privs is disabled.
func (r *Rule) analyzeCompositionNoNewPrivsDelayedPrivilegeTransitionCapability() {
	privilegeTransitionCaps := []string{"CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETFCAP"}

	for nnpIdx := range r.Signals {
		nnpSignal := r.Signals[nnpIdx]
		if !isNoNewPrivsDisabledSignal(nnpSignal) {
			continue
		}

		thread := signalThread(nnpSignal)
		if thread == nil {
			continue
		}

		capIndexes := make([]int, 0)
		for i := range r.Signals {
			sig := r.Signals[i]
			if !signalMentionsThread(sig, thread.Tid) {
				continue
			}
			if isAnyCapabilitySignal(sig, privilegeTransitionCaps, "permitted", "ambient", "inheritable") {
				capIndexes = append(capIndexes, i)
			}
		}
		if len(capIndexes) == 0 {
			continue
		}

		capabilityNames := capabilityNamesFromSignals(r.Signals, capIndexes)
		evidence := []string{
			nnpSignal.Title,
			fmt.Sprintf("Delayed privilege-transition capabilities on tid=%d: %s", thread.Tid, strings.Join(capabilityNames, ", ")),
		}
		for _, idx := range capIndexes {
			evidence = append(evidence, r.Signals[idx].Title)
		}

		signal := newCompositionSignal(
			HighRisk,
			"NoNewPrivs disabled combined with delayed privilege-transition capability",
			fmt.Sprintf("Thread %d does not enable no_new_privs and still retains privilege-transition capabilities outside CapEff, so later execve paths can regain stronger identity or capability state than the current thread surface suggests.", thread.Tid),
			"Enable no_new_privs unless a reviewed privilege transition is required, and remove CAP_SETUID, CAP_SETGID, CAP_SETPCAP, or CAP_SETFCAP from permitted, ambient, and inheritable sets that are not strictly needed.",
			thread,
			nil,
			nil,
			evidence,
		)
		covered := append([]int{nnpIdx}, capIndexes...)
		r.appendComposition(signal, covered...)
	}
}

// analyzeCompositionCAPSysChrootMountNamespaceDeviation finds threads
// that combine CAP_SYS_CHROOT with thread-level mount namespace
// deviation.
func (r *Rule) analyzeCompositionCAPSysChrootMountNamespaceDeviation() {
	for capIdx := range r.Signals {
		capSignal := r.Signals[capIdx]
		if !isCapabilitySignal(capSignal, "CAP_SYS_CHROOT", "effective", "permitted") {
			continue
		}

		thread := signalThread(capSignal)
		if thread == nil {
			continue
		}

		nsIdx := -1
		for i := range r.Signals {
			if isMountNamespaceDeviationSignalForThread(r.Signals[i], thread) {
				nsIdx = i
				break
			}
		}
		if nsIdx == -1 {
			continue
		}

		mntNS := thread.MntNS
		signal := newCompositionSignal(
			HighRisk,
			"CAP_SYS_CHROOT combined with thread-level mount namespace deviation",
			fmt.Sprintf("Thread %d already runs in a different mount namespace than its main thread and also retains CAP_SYS_CHROOT, so filesystem-view transitions inside the process are weaker and easier to misuse than either signal alone suggests.", thread.Tid),
			"Keep all threads in one reviewed mount namespace unless the split is intentional, and drop CAP_SYS_CHROOT from workloads that do not explicitly manage roots or mount-namespace transitions.",
			thread,
			&mntNS,
			nil,
			[]string{
				capSignal.Title,
				r.Signals[nsIdx].Title,
				fmt.Sprintf("tid=%d, tgid=%d, mntns=%s", thread.Tid, thread.Tgid, formatNSRef(thread.MntNS)),
			},
		)
		r.appendComposition(signal, capIdx, nsIdx)
	}
}

// analyzeCompositionCAPKillHostPIDNamespace finds threads that combine
// CAP_KILL with the host PID namespace.
func (r *Rule) analyzeCompositionCAPKillHostPIDNamespace() {
	for capIdx := range r.Signals {
		capSignal := r.Signals[capIdx]
		if !isCapabilitySignal(capSignal, "CAP_KILL", "effective", "permitted") {
			continue
		}

		thread := signalThread(capSignal)
		if thread == nil {
			continue
		}

		nsIdx := -1
		for i := range r.Signals {
			if isHostPIDNamespaceSignalForThread(r.Signals[i], thread) {
				nsIdx = i
				break
			}
		}
		if nsIdx == -1 {
			continue
		}

		pidNS := thread.PIDNS
		signal := newCompositionSignal(
			Fatal,
			"CAP_KILL combined with host PID namespace",
			fmt.Sprintf("Thread %d can bypass ordinary signal permission checks while sharing the host PID namespace, so it can directly disrupt or terminate host-visible processes instead of staying confined to an isolated process set.", thread.Tid),
			"Drop CAP_KILL unless the workload explicitly brokers signals, and keep the workload in a private PID namespace so signal scope does not reach host-visible processes.",
			thread,
			&pidNS,
			nil,
			[]string{
				capSignal.Title,
				r.Signals[nsIdx].Title,
				fmt.Sprintf("tid=%d, tgid=%d, pidns=%s", thread.Tid, thread.Tgid, formatNSRef(thread.PIDNS)),
			},
		)
		r.appendComposition(signal, capIdx, nsIdx)
	}
}

// AnalyzeComposition runs all composition-signal synthesis rules.
func (r *Rule) AnalyzeComposition() {
	r.analyzeCompositionCAPSysPtraceHostPIDNamespace()
	r.analyzeCompositionCAPSysAdminNonPrivateMountPropagation()
	r.analyzeCompositionCAPDACOverrideWritableHostMount()
	r.analyzeCompositionUnconfinedSeccompHighRiskCapability()
	r.analyzeCompositionNoNewPrivsDelayedPrivilegeTransitionCapability()
	r.analyzeCompositionCAPSysChrootMountNamespaceDeviation()
	r.analyzeCompositionCAPKillHostPIDNamespace()
}
