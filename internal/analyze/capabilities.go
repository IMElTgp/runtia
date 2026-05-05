package analyze

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

const ( //                               severity
	CAP_CHOWN              = iota //  2
	CAP_DAC_OVERRIDE              //  5
	CAP_DAC_READ_SEARCH           //  5
	CAP_FOWNER                    //  3
	CAP_FSETID                    //  2
	CAP_KILL                      //  2
	CAP_SETGID                    //  3
	CAP_SETUID                    //  3
	CAP_SETPCAP                   //  4
	CAP_LINUX_IMMUTABLE           //  3
	CAP_NET_BIND_SERVICE          // 1
	CAP_NET_BROADCAST             // 1 (not utilized yet)
	CAP_NET_ADMIN                 // 5
	CAP_NET_RAW                   // 4
	CAP_IPC_LOCK                  // 3
	CAP_IPC_OWNER                 // 3
	CAP_SYS_MODULE                // 5
	CAP_SYS_RAWIO                 // 5
	CAP_SYS_CHROOT                // 3
	CAP_SYS_PTRACE                // 5
	CAP_SYS_PACCT                 // 2
	CAP_SYS_ADMIN                 // 5
	CAP_SYS_BOOT                  // 5
	CAP_SYS_NICE                  // 3
	CAP_SYS_RESOURCE              // 4
	CAP_SYS_TIME                  // 4
	CAP_SYS_TTY_CONFIG            // 2
	CAP_MKNOD                     // 4
	CAP_LEASE                     // 3
	CAP_AUDIT_WRITE               // 2
	CAP_AUDIT_CONTROL             // 4
	CAP_SETFCAP                   // 4
	CAP_MAC_OVERRIDE              // 4
	CAP_MAC_ADMIN                 // 4
	CAP_SYSLOG                    // 3
	CAP_WAKE_ALARM                // 2
	CAP_BLOCK_SUSPEND             // 2
	CAP_AUDIT_READ                // 3
	CAP_PERFMON                   // 4
	CAP_BPF                       // 5
	CAP_CHECKPOINT_RESTORE        // 4
)

var capThreatLevels = []int{
	LowRisk, Fatal, Fatal, MediumRisk, LowRisk, LowRisk, MediumRisk, MediumRisk, HighRisk, MediumRisk,
	Info, Info, Fatal, HighRisk, MediumRisk, MediumRisk, Fatal, Fatal, MediumRisk, Fatal,
	LowRisk, Fatal, Fatal, MediumRisk, HighRisk, HighRisk, LowRisk, HighRisk, MediumRisk, LowRisk,
	HighRisk, HighRisk, HighRisk, HighRisk, MediumRisk, LowRisk, LowRisk, MediumRisk, HighRisk, Fatal,
	HighRisk,
}

func capabilitySetLabel(capType string) string {
	switch capType {
	case "eff":
		return "effective"
	case "prm":
		return "permitted"
	case "amb":
		return "ambient"
	case "inh":
		return "inheritable"
	case "bnd":
		return "bounding"
	default:
		return capType
	}
}

func capabilitySetField(capType string) string {
	switch capType {
	case "eff":
		return "CapEff"
	case "prm":
		return "CapPrm"
	case "amb":
		return "CapAmb"
	case "inh":
		return "CapInh"
	case "bnd":
		return "CapBnd"
	default:
		return "Cap" + capType
	}
}

// capabilitySetContext returns description for each capability type
func capabilitySetContext(capType string) string {
	switch capType {
	case "eff":
		return "This capability is active for current kernel permission checks."
	case "prm":
		return "It is not necessarily active, but it is available for the thread to make effective."
	case "amb":
		return "It may be preserved across execve and passed to non-privileged programs."
	case "inh":
		return "It may participate in capability inheritance across execve when file capability rules allow it."
	case "bnd":
		return "It remains in the bounding set, so it has not been removed from the capabilities that can be gained across execve."
	default:
		return "This capability is present on the thread."
	}
}

// setCapabilityText sets Title and Summary for each signal
func setCapabilityText(s *model.Signal, capType, capName, impact string) *model.Signal {
	if s == nil {
		return nil
	}

	label := capabilitySetLabel(capType)
	s.Title = "Thread has " + capName + " in its " + label + " capability set"
	s.Summary = "The thread has " + capName + " in its " + label + " capability set. " + capabilitySetContext(capType) + " " + impact
	return s
}

func concerningCap(t *target.Thread, capType string) (capacity uint64) {
	switch capType {
	case "eff":
		return t.CapEff
	case "prm":
		return t.CapPrm
	case "inh":
		return t.CapInh
	case "amb":
		return t.CapAmb
	case "bnd":
		return t.CapBnd
	}
	return
}

func formatNSRef(ns target.NSRef) string {
	if ns.Type == "" && ns.Dev == 0 && ns.Ino == 0 {
		return "unknown"
	}
	return fmt.Sprintf("%s:%d:%d", ns.Type, ns.Dev, ns.Ino)
}

func addCapabilityEvidence(s *model.Signal, capType, capName string) {
	if s == nil {
		return
	}
	if len(s.RelativeThreads) == 0 || s.RelativeThreads[0] == nil {
		s.Evidence = append(s.Evidence, fmt.Sprintf("%s is present in %s", capName, capabilitySetField(capType)))
		return
	}

	t := s.RelativeThreads[0]
	s.Evidence = append(s.Evidence, []string{
		fmt.Sprintf("tid=%d, tgid=%d, comm=%q, main_thread=%t", t.Tid, t.Tgid, strings.TrimSpace(t.Comm), t.IsMainThread),
		fmt.Sprintf("%s=0x%016x includes %s", capabilitySetField(capType), concerningCap(t, capType), capName),
		fmt.Sprintf("userns=%s, mntns=%s, pidns=%s", formatNSRef(t.UserNS), formatNSRef(t.MntNS), formatNSRef(t.PIDNS)),
	}...)
}

func capabilitySetRecommendation(capType, capName string) string {
	switch capType {
	case "eff":
		return "Drop " + capName + " from CapEff unless the workload has a reviewed, narrow need for it."
	case "prm":
		return "Remove " + capName + " from CapPrm so the thread cannot make it effective later."
	case "amb":
		return "Remove " + capName + " from CapAmb so it cannot survive execve into non-privileged programs."
	case "inh":
		return "Remove " + capName + " from CapInh unless a reviewed file-capability exec path requires it."
	case "bnd":
		return "Drop " + capName + " from CapBnd so it cannot be regained through execve or file capabilities."
	default:
		return "Remove " + capName + " unless it is explicitly required."
	}
}

func capabilityCommonRecommendation(s *model.Signal, capType, capName, hardening, composite string) string {
	parts := []string{
		capabilitySetRecommendation(capType, capName),
		hardening,
	}

	if s != nil && s.RiskLevel >= HighRisk {
		parts = append(parts, "For ordinary application containers, require an explicit exception before retaining this capability.")
	}
	if s != nil && s.RiskLevel >= MediumRisk && capType != "bnd" {
		parts = append(parts, "Keep seccomp filtering enabled; when this capability is combined with SeccompMode 0, treat the workload as a stronger hardening priority.")
	}
	if composite != "" {
		parts = append(parts, "Check possible composite exposure: "+composite)
	}

	return strings.Join(parts, " ")
}

func setCapabilityDetails(s *model.Signal, capType, capName, impact, hardening, composite string) *model.Signal {
	s = setCapabilityText(s, capType, capName, impact)
	addCapabilityEvidence(s, capType, capName)
	if s != nil {
		s.Recommendation = capabilityCommonRecommendation(s, capType, capName, hardening, composite)
	}
	return s
}

//goland:noinspection ALL
func handler_CAP_CHOWN(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_CHOWN",
		"It can change file owner and group IDs, so writable files or host mounts can become a stronger escalation path.",
		"Prefer read-only mounts for host or sensitive paths and avoid granting write access to files whose ownership controls access.",
		"writable host or sensitive mounts can let ownership changes support persistence or privilege escalation.",
	)
}

func handler_CAP_DAC_OVERRIDE(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_DAC_OVERRIDE",
		"It can bypass discretionary file read, write, and execute permission checks for reachable files.",
		"Remove writable host paths and mount sensitive paths read-only with nodev, nosuid, and noexec where possible.",
		"sensitive writable mounts such as /host, /rootfs, /etc, /run, or /var/run can turn DAC bypass into a host-impacting issue.",
	)
}

func handler_CAP_DAC_READ_SEARCH(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_DAC_READ_SEARCH",
		"It can bypass file read and directory search permission checks and enables paths such as open_by_handle_at.",
		"Keep host paths out of the mount namespace unless they are read-only and strictly scoped.",
		"sensitive host mounts can expose files that normal DAC checks would otherwise protect.",
	)
}

func handler_CAP_FOWNER(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_FOWNER",
		"It can bypass many ownership checks for file operations, including permission changes, ACL updates, sticky-bit deletions, and O_NOATIME use.",
		"Drop this capability for ordinary services and avoid writable sensitive mounts where metadata changes matter.",
		"writable host or shared mounts can make ownership-check bypasses affect files outside the intended container boundary.",
	)
}

func handler_CAP_FSETID(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_FSETID",
		"It can preserve or set set-user-ID and set-group-ID bits where they would normally be cleared or rejected.",
		"Use nosuid on writable mounts and remove unnecessary setuid or setgid files from the image.",
		"writable executable paths with setuid or setgid files can preserve privilege-transition paths.",
	)
}

func handler_CAP_KILL(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_KILL",
		"It can bypass permission checks for sending signals, which is more sensitive when the container shares a PID namespace.",
		"Use a private PID namespace and avoid running unrelated processes in the same PID namespace.",
		"a shared PID namespace or multiple different Tgid values in the same namespace can let this thread disrupt other processes.",
	)
}

func handler_CAP_SETGID(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SETGID",
		"It can change group IDs, set supplementary groups, forge UNIX socket GID credentials, and write GID mappings in a user namespace.",
		"Drop it unless the process must manage identities; keep user namespace mappings minimal and reviewed.",
		"broad GID mappings, writable files, or shared UNIX sockets can make group changes affect more resources than expected.",
	)
}

func handler_CAP_SETUID(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SETUID",
		"It can change user IDs, forge UNIX socket UID credentials, and write UID mappings in a user namespace.",
		"Drop it for fixed-identity services and combine user namespace use with no_new_privs where possible.",
		"broad UID mappings, setuid files, or sensitive writable mounts can turn UID changes into stronger privilege transitions.",
	)
}

func handler_CAP_SETPCAP(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SETPCAP",
		"It can modify capability state, alter inheritable capabilities, drop capabilities from the bounding set, and change securebits.",
		"Keep capability sets fixed at container start and remove this capability from processes that do not manage capabilities intentionally.",
		"permitted, ambient, inheritable, or bounding capabilities can be reshaped into later privilege changes.",
	)
}

func handler_CAP_LINUX_IMMUTABLE(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_LINUX_IMMUTABLE",
		"It can set immutable and append-only inode flags, which can cause persistence or denial of service on writable mounts.",
		"Keep host and configuration mounts read-only and drop this capability unless immutable flags are the workload's purpose.",
		"writable host, configuration, or log mounts can be made hard to repair by immutable or append-only flags.",
	)
}

func handler_CAP_NET_BIND_SERVICE(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_NET_BIND_SERVICE",
		"It allows binding Internet ports below 1024; this is usually low risk but should still be scoped to workloads that need privileged ports.",
		"Prefer high container ports with runtime port mapping when the process does not need to bind privileged ports itself.",
		"host networking can make privileged-port binding affect the host network namespace directly.",
	)
}

func handler_CAP_NET_BROADCAST(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_NET_BROADCAST",
		"It is a historical capability for socket broadcast and multicast behavior, and most workloads have no reason to keep it.",
		"Drop it unless the workload has a specific legacy networking requirement.",
		"shared or host network namespaces make unnecessary network capabilities harder to justify.",
	)
}

func handler_CAP_NET_ADMIN(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_NET_ADMIN",
		"It can configure network interfaces, routing, firewall state, traffic controls, promiscuous mode, and privileged socket options.",
		"Use a private network namespace and move network setup into a short-lived, tightly scoped init step when possible.",
		"host networking lets this capability alter host interfaces, routes, firewall state, or traffic controls.",
	)
}

func handler_CAP_NET_RAW(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_NET_RAW",
		"It can create raw and packet sockets, enabling packet spoofing, sniffing, and broader network attack surface.",
		"Drop it for services that do not need raw sockets and keep seccomp or LSM policy blocking raw socket creation where possible.",
		"shared or host network namespaces can turn raw sockets into packet sniffing or spoofing paths outside the workload.",
	)
}

func handler_CAP_IPC_LOCK(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_IPC_LOCK",
		"It can lock memory and allocate huge pages, which can create resource pressure or keep sensitive memory resident.",
		"Set tight memlock and memory cgroup limits before retaining this capability.",
		"large locked-memory allocations can combine with weak resource limits into denial-of-service pressure.",
	)
}

func handler_CAP_IPC_OWNER(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_IPC_OWNER",
		"It can bypass System V IPC object permission checks, especially when IPC namespaces are shared.",
		"Use a private IPC namespace and drop this capability unless the process manages IPC objects by design.",
		"shared IPC namespaces can let this thread bypass permissions on IPC objects owned by other processes.",
	)
}

func handler_CAP_SYS_MODULE(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SYS_MODULE",
		"It can load and unload kernel modules, which effectively permits code to run in the kernel.",
		"Do not grant this capability to containers; keep module loading on the host control plane only.",
		"access to host module paths or disabled seccomp can make module loading a direct host-kernel compromise path.",
	)
}

func handler_CAP_SYS_RAWIO(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SYS_RAWIO",
		"It can access raw I/O interfaces, kernel memory, I/O ports, MSR devices, and low-level device commands.",
		"Do not grant it to containers; block host devices with device cgroups and avoid mounting /dev, /proc/kcore, /dev/mem, or MSR devices.",
		"writable or exposed device paths can combine with raw I/O into host-level compromise.",
	)
}

func handler_CAP_SYS_CHROOT(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SYS_CHROOT",
		"It can use chroot and setns into mount namespaces, which is mostly a composition risk with mounts and other privileges.",
		"Drop it unless the workload intentionally manages roots; keep mount namespaces private and sensitive mounts read-only.",
		"writable root-like mounts or mount namespace transitions can make chroot part of a broader escape path.",
	)
}

func handler_CAP_SYS_PTRACE(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SYS_PTRACE",
		"It can trace, inspect, and modify other processes and their memory, especially with shared PID namespaces or same-UID processes.",
		"Use a private PID namespace and retain this only for dedicated debuggers or profilers with explicit isolation.",
		"multiple different Tgid values in the same PID namespace can let this thread inspect or modify other processes.",
	)
}

func handler_CAP_SYS_PACCT(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SYS_PACCT",
		"It can enable or disable process accounting; this is usually narrow but not needed by ordinary application containers.",
		"Drop it unless the container is a dedicated accounting component.",
		"host or shared accounting state can let this affect visibility for processes outside the workload.",
	)
}

func handler_CAP_SYS_ADMIN(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SYS_ADMIN",
		"It covers broad system-administration operations including mounts, namespace operations, privileged ioctls, and many overloaded kernel controls.",
		"Replace it with narrower capabilities or a short-lived helper; keep /proc/sys, /sys, cgroup paths, and host mounts read-only or absent.",
		"disabled seccomp, writable /proc/sys, writable sysfs/cgroup paths, or sensitive mounts can turn this into a fatal container boundary issue.",
	)
}

func handler_CAP_SYS_BOOT(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SYS_BOOT",
		"It can reboot the system or load a new kernel through kexec, creating host-level denial-of-service or takeover risk.",
		"Do not grant it to containers; block reboot and kexec paths with seccomp as a defense-in-depth layer.",
		"host namespaces or disabled seccomp can make reboot or kexec attempts affect the host directly.",
	)
}

func handler_CAP_SYS_NICE(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SYS_NICE",
		"It can change scheduling policy, priority, CPU affinity, I/O priority, and memory placement, creating resource-control and denial-of-service risk.",
		"Drop it unless the workload is a scheduler or real-time component; enforce CPU, memory, and I/O cgroup limits.",
		"weak resource limits can let scheduling and affinity changes starve other processes.",
	)
}

func handler_CAP_SYS_RESOURCE(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SYS_RESOURCE",
		"It can raise or bypass resource limits, quotas, reserved filesystem space, pipe and message queue limits, and related resource controls.",
		"Drop it for ordinary services and enforce resource ceilings through cgroups outside the container.",
		"weak cgroup or quota boundaries can let this bypass local resource controls and increase denial-of-service impact.",
	)
}

func handler_CAP_SYS_TIME(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SYS_TIME",
		"It can set system and hardware clocks, affecting logs, authentication, certificate validity, and distributed-system assumptions.",
		"Do not grant it to application containers; use host time synchronization outside the workload.",
		"shared time assumptions can make clock changes affect logs, TLS, tokens, or clustered systems outside the process.",
	)
}

func handler_CAP_SYS_TTY_CONFIG(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SYS_TTY_CONFIG",
		"It can perform privileged TTY operations such as vhangup and virtual terminal ioctls.",
		"Drop it unless the workload is a trusted terminal manager and avoid exposing host consoles or TTY devices.",
		"mounted console or TTY devices can turn this into disruption of host or shared terminal sessions.",
	)
}

func handler_CAP_MKNOD(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_MKNOD",
		"It can create device nodes; combined with permissive device cgroups or host mounts this can expose host devices.",
		"Drop it and keep /dev or device-related paths non-writable; enforce a restrictive device cgroup policy.",
		"writable /dev or device-related mounts can let this create device nodes that reach host devices.",
	)
}

func handler_CAP_LEASE(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_LEASE",
		"It can place leases on arbitrary files, which can block or disrupt other processes' file access.",
		"Drop it unless file lease management is the workload's purpose and keep shared writable mounts minimal.",
		"shared writable files can be leased to disrupt other processes that need them.",
	)
}

func handler_CAP_AUDIT_WRITE(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_AUDIT_WRITE",
		"It can write to the kernel audit log, which can pollute or obscure audit evidence.",
		"Drop it unless the container is a trusted audit component and route application logs through normal logging paths.",
		"shared audit visibility can let noisy or misleading audit records obscure host or workload events.",
	)
}

func handler_CAP_AUDIT_CONTROL(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_AUDIT_CONTROL",
		"It can enable, disable, or modify kernel audit rules, weakening audit visibility.",
		"Do not grant it to application containers; keep audit policy controlled by the host.",
		"host audit configuration exposure can let this reduce or disable security visibility.",
	)
}

func handler_CAP_SETFCAP(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SETFCAP",
		"It can set file capabilities and affects some user-namespace UID 0 mapping paths, enabling capability persistence or transfer.",
		"Use read-only or noexec/nosuid writable mounts and remove this capability unless the process intentionally manages file capabilities.",
		"rw executable mounts without noexec can let this persist or transfer capabilities through files.",
	)
}

func handler_CAP_MAC_OVERRIDE(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_MAC_OVERRIDE",
		"It can bypass Smack mandatory access control checks where Smack is active.",
		"Drop it unless the deployment intentionally uses Smack and this process is trusted to bypass policy.",
		"on Smack-enabled hosts, this can bypass MAC policy that would otherwise contain filesystem or IPC access.",
	)
}

func handler_CAP_MAC_ADMIN(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_MAC_ADMIN",
		"It can manage Smack mandatory access control policy and state where Smack is active.",
		"Drop it unless the container is a trusted Smack policy manager.",
		"on Smack-enabled hosts, this can weaken or alter MAC policy for other subjects.",
	)
}

func handler_CAP_SYSLOG(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_SYSLOG",
		"It can perform privileged syslog operations and may expose kernel messages or addresses depending on kernel settings.",
		"Drop it and rely on normal log collection; keep kernel logs and address exposure controlled by the host.",
		"host kernel log access can leak security events, kernel addresses, or other workload activity.",
	)
}

func handler_CAP_WAKE_ALARM(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_WAKE_ALARM",
		"It can program timers that wake the system, affecting power and wakeup behavior.",
		"Drop it unless wake timers are a documented workload requirement.",
		"host-level power management can be affected when wake alarms are allowed from the container.",
	)
}

func handler_CAP_BLOCK_SUSPEND(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_BLOCK_SUSPEND",
		"It can block system suspend, affecting availability and power management.",
		"Drop it unless the workload is explicitly trusted to control suspend behavior.",
		"host power-management policy can be disrupted if suspend blockers are allowed from the container.",
	)
}

func handler_CAP_AUDIT_READ(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_AUDIT_READ",
		"It can read audit records through multicast netlink, potentially exposing host or other workload security events.",
		"Drop it unless the container is a trusted audit reader and minimize host audit event exposure.",
		"shared audit streams can leak host or other workload security events.",
	)
}

func handler_CAP_PERFMON(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_PERFMON",
		"It can use performance monitoring mechanisms such as perf_event_open, which may leak cross-process or cross-container information.",
		"Drop it for ordinary services and keep perf_event access restricted by host policy.",
		"shared PID namespaces or broad perf access can leak behavior from other processes or containers.",
	)
}

func handler_CAP_BPF(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_BPF",
		"It can perform privileged BPF operations that observe or influence kernel and network paths.",
		"Do not grant it to application containers; keep BPF loading in trusted host components and enforce seccomp and LSM restrictions.",
		"CAP_PERFMON, CAP_NET_ADMIN, disabled seccomp, or exposed bpffs can make BPF programs observe or affect host activity.",
	)
}

func handler_CAP_CHECKPOINT_RESTORE(s *model.Signal, capType string) *model.Signal {
	return setCapabilityDetails(
		s,
		capType,
		"CAP_CHECKPOINT_RESTORE",
		"It can use checkpoint/restore features such as setting ns_last_pid, clone3 set_tid, and reading other processes' map_files links.",
		"Drop it unless this is a dedicated checkpoint/restore component running with private PID isolation.",
		"shared PID namespaces can expose other processes' map_files links or make PID manipulation affect more than the target workload.",
	)
}

// downgradeRiskLevel determines whether to downgrade riskLevel for certain capabilities
// according to capType (eff, prm and amb, inh, bnd)
func downgradeRiskLevel(capability uint64, risk int, capType string) int {
	blackList := map[uint64]bool{
		CAP_SYS_ADMIN:          true, // TOO heavy
		CAP_SYS_MODULE:         true, // loading and unloading kernel modules
		CAP_SYS_RAWIO:          true, // concerning borders between kernel and hardware
		CAP_SYS_PTRACE:         true, // check/trace/rw thread status
		CAP_SYS_BOOT:           true, // reboot/kexec, which are not the capabilities that a container needs
		CAP_BPF:                true, // concerning eBPF
		CAP_PERFMON:            true, // concerning perf
		CAP_CHECKPOINT_RESTORE: true, // affect PID/read map_files of other threads
		CAP_DAC_OVERRIDE:       true, // bypass DAC check
		CAP_DAC_READ_SEARCH:    true, // bypass DAC check
		CAP_NET_ADMIN:          true, // net admin capability
		CAP_SETPCAP:            true, // adjust capabilities
		CAP_SETFCAP:            true, // set capabilities
	}

	if blackList[capability] {
		return risk
	}

	switch capType {
	case "eff":
		return risk
	case "amb", "prm":
		return min(risk, max(Info, risk-1))
	case "inh":
		return min(risk, max(Info, risk-2))
	case "bnd":
		return min(risk, max(Safe, risk-3))
	}

	return risk
}

// mntnsForThread returns the mntns snapshot of given thread
func (r *Rule) mntnsForThread(thread *target.Thread) *model.NamespaceSnapshot {
	for i := range r.Snapshot.MountNamespaces {
		ns := &r.Snapshot.MountNamespaces[i]
		if ns.NSRef == thread.MntNS {
			return ns
		}
	}
	return nil
}

// mntInfo2mntPoint extracts mount points from a slice of mount infos
func mntInfo2mntPoint(mntInfos []collect.MountInfo) []string {
	mntPoints := make([]string, 0)
	for _, mntInfo := range mntInfos {
		mntPoints = append(mntPoints, mntInfo.MountPoint)
	}
	return mntPoints
}

func (r *Rule) mountPointsForThread(thread *target.Thread) []string {
	mntns := r.mntnsForThread(thread)
	if mntns == nil {
		return nil
	}
	return mntInfo2mntPoint(mntns.MountInfo)
}

// analyzeCapabilitiesPerThread analyzes the
// capabilities (counted from /proc/sys/kernel/cap_last_cap) status and forms
// findings on risky results
func (r *Rule) analyzeCapabilitiesPerThread(t *target.Thread, capLastCap int) {
	capCount := min(capLastCap+1, len(capThreatLevels))

	var signalCapEff []*model.Signal
	var signalCapPrm []*model.Signal
	var signalCapAmb []*model.Signal
	var signalCapInh []*model.Signal
	var signalCapBnd []*model.Signal
	var appendedCaps uint64
	capAppended := func(cap int) bool {
		return (appendedCaps & (uint64(1) << uint(cap))) != 0
	}
	appendCap := func(cap int) {
		appendedCaps |= uint64(1) << uint(cap)
	}

	newCapabilitySignal := func(riskLevel int) *model.Signal {
		return &model.Signal{
			Finding: model.Finding{
				Category:        "capabilities",
				RiskLevel:       riskLevel,
				RelativeThreads: []*target.Thread{t},
				MountPoint:      r.mountPointsForThread(t), // mount points of the thread's belonging mnt ns
			},
		}
	}

	// CapEff: most sensitive
	capeff := t.CapEff
	for i := range capCount {
		// if a capability is available both in high priority and low priority cap types (e.g. CapEff and CapAmb),
		// keep the signal in the former case and abandon the latter case to avoid repeating
		// that's why the if-branch condition contains `!capAppended(i)`
		if (capeff&1) != 0 && !capAppended(i) {
			// Composite cases are left as recommendations for now rather than risk escalation.
			signal := newCapabilitySignal(downgradeRiskLevel(uint64(i), capThreatLevels[i], "eff"))
			signal = switchCapabilities(i, signal, "eff")
			signalCapEff = append(signalCapEff, signal)
			appendCap(i)
		}
		// right shift 1 bit to process the next capability
		capeff >>= 1
	}

	// CapPrm and CapAmb: sensitive
	capprm, capamb := t.CapPrm, t.CapAmb
	for i := range capCount {
		if (capprm&1) != 0 && !capAppended(i) {
			signal := newCapabilitySignal(downgradeRiskLevel(uint64(i), capThreatLevels[i], "prm"))
			signal = switchCapabilities(i, signal, "prm")
			signalCapPrm = append(signalCapPrm, signal)
			appendCap(i)
		}
		if (capamb&1) != 0 && !capAppended(i) {
			signal := newCapabilitySignal(downgradeRiskLevel(uint64(i), capThreatLevels[i], "amb"))
			signal = switchCapabilities(i, signal, "amb")
			signalCapAmb = append(signalCapAmb, signal)
			appendCap(i)
		}
		capprm >>= 1
		capamb >>= 1
	}

	// CapInh: less sensitive
	capinh := t.CapInh
	for i := range capCount {
		if (capinh&1) != 0 && !capAppended(i) {
			signal := newCapabilitySignal(downgradeRiskLevel(uint64(i), capThreatLevels[i], "inh"))
			signal = switchCapabilities(i, signal, "inh")
			signalCapInh = append(signalCapInh, signal)
			appendCap(i)
		}
		capinh >>= 1
	}

	// CapBnd: least sensitive
	capbnd := t.CapBnd
	for i := range capCount {
		if (capbnd&1) != 0 && !capAppended(i) {
			signal := newCapabilitySignal(downgradeRiskLevel(uint64(i), capThreatLevels[i], "bnd"))
			signal = switchCapabilities(i, signal, "bnd")
			signalCapBnd = append(signalCapBnd, signal)
			appendCap(i)
		}
		capbnd >>= 1
	}

	appendSignals := func(signals []*model.Signal) {
		for _, signal := range signals {
			r.Signals = append(r.Signals, *signal)
		}
	}

	appendSignals(signalCapEff)
	appendSignals(signalCapPrm)
	appendSignals(signalCapAmb)
	appendSignals(signalCapInh)
	appendSignals(signalCapBnd)
}

func kernelCapLastCap() int {
	defaultCapLastCap := len(capThreatLevels) - 1

	raw, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return defaultCapLastCap
	}

	capLastCap, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || capLastCap < 0 {
		return defaultCapLastCap
	}
	return capLastCap
}

// AnalyzeCapabilities is the main entry function of internal/analyze/capabilities.go
func (r *Rule) AnalyzeCapabilities() {
	capLastCap := kernelCapLastCap()
	for _, threadSnapshot := range r.Snapshot.Threads {
		thread := target.Thread(threadSnapshot)
		r.analyzeCapabilitiesPerThread(&thread, capLastCap)
	}
}

func switchCapabilities(cap int, s *model.Signal, capType string) *model.Signal {
	switch cap {
	case CAP_CHOWN:
		return handler_CAP_CHOWN(s, capType)
	case CAP_DAC_OVERRIDE:
		return handler_CAP_DAC_OVERRIDE(s, capType)
	case CAP_DAC_READ_SEARCH:
		return handler_CAP_DAC_READ_SEARCH(s, capType)
	case CAP_FOWNER:
		return handler_CAP_FOWNER(s, capType)
	case CAP_FSETID:
		return handler_CAP_FSETID(s, capType)
	case CAP_KILL:
		return handler_CAP_KILL(s, capType)
	case CAP_SETGID:
		return handler_CAP_SETGID(s, capType)
	case CAP_SETUID:
		return handler_CAP_SETUID(s, capType)
	case CAP_SETPCAP:
		return handler_CAP_SETPCAP(s, capType)
	case CAP_LINUX_IMMUTABLE:
		return handler_CAP_LINUX_IMMUTABLE(s, capType)
	case CAP_NET_BIND_SERVICE:
		return handler_CAP_NET_BIND_SERVICE(s, capType)
	case CAP_NET_BROADCAST:
		return handler_CAP_NET_BROADCAST(s, capType)
	case CAP_NET_ADMIN:
		return handler_CAP_NET_ADMIN(s, capType)
	case CAP_NET_RAW:
		return handler_CAP_NET_RAW(s, capType)
	case CAP_IPC_LOCK:
		return handler_CAP_IPC_LOCK(s, capType)
	case CAP_IPC_OWNER:
		return handler_CAP_IPC_OWNER(s, capType)
	case CAP_SYS_MODULE:
		return handler_CAP_SYS_MODULE(s, capType)
	case CAP_SYS_RAWIO:
		return handler_CAP_SYS_RAWIO(s, capType)
	case CAP_SYS_CHROOT:
		return handler_CAP_SYS_CHROOT(s, capType)
	case CAP_SYS_PTRACE:
		return handler_CAP_SYS_PTRACE(s, capType)
	case CAP_SYS_PACCT:
		return handler_CAP_SYS_PACCT(s, capType)
	case CAP_SYS_ADMIN:
		return handler_CAP_SYS_ADMIN(s, capType)
	case CAP_SYS_BOOT:
		return handler_CAP_SYS_BOOT(s, capType)
	case CAP_SYS_NICE:
		return handler_CAP_SYS_NICE(s, capType)
	case CAP_SYS_RESOURCE:
		return handler_CAP_SYS_RESOURCE(s, capType)
	case CAP_SYS_TIME:
		return handler_CAP_SYS_TIME(s, capType)
	case CAP_SYS_TTY_CONFIG:
		return handler_CAP_SYS_TTY_CONFIG(s, capType)
	case CAP_MKNOD:
		return handler_CAP_MKNOD(s, capType)
	case CAP_LEASE:
		return handler_CAP_LEASE(s, capType)
	case CAP_AUDIT_WRITE:
		return handler_CAP_AUDIT_WRITE(s, capType)
	case CAP_AUDIT_CONTROL:
		return handler_CAP_AUDIT_CONTROL(s, capType)
	case CAP_SETFCAP:
		return handler_CAP_SETFCAP(s, capType)
	case CAP_MAC_OVERRIDE:
		return handler_CAP_MAC_OVERRIDE(s, capType)
	case CAP_MAC_ADMIN:
		return handler_CAP_MAC_ADMIN(s, capType)
	case CAP_SYSLOG:
		return handler_CAP_SYSLOG(s, capType)
	case CAP_WAKE_ALARM:
		return handler_CAP_WAKE_ALARM(s, capType)
	case CAP_BLOCK_SUSPEND:
		return handler_CAP_BLOCK_SUSPEND(s, capType)
	case CAP_AUDIT_READ:
		return handler_CAP_AUDIT_READ(s, capType)
	case CAP_PERFMON:
		return handler_CAP_PERFMON(s, capType)
	case CAP_BPF:
		return handler_CAP_BPF(s, capType)
	case CAP_CHECKPOINT_RESTORE:
		return handler_CAP_CHECKPOINT_RESTORE(s, capType)
	default:
		return s
	}
}

// ParseCapabilityNameFromFinding parses relative capability name
// from a capabilities-related signal
func ParseCapabilityNameFromFinding(finding *model.Finding) string {
	title := strings.TrimPrefix(finding.Title, "Thread has ")
	title = strings.TrimSuffix(title, " capability set")
	capName, _, _ := strings.Cut(title, " in this ")
	return capName
}
