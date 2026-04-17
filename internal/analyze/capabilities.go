package analyze

import (
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
	CAP_BLOCK_SYSPEND             // 2
	CAP_AUDIT_READ                // 3
	CAP_PERFMON                   // 4
	CAP_BPF                       // 5
	CAP_CHECKPOINT_RESTORE        // 4
)

var capThreatLevels = []int{
	2, 5, 5, 3, 2, 2, 3, 3, 4, 3, 1, 1, 5, 4, 3, 3, 5, 5, 3, 5, 2, 5, 5, 3, 4, 4, 2, 4, 3, 2, 4, 4, 4, 4, 3, 2, 2, 3, 4, 5, 4,
}

func CAP_CHOWN_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_DAC_OVERRIDE_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_DAC_READ_SEARCH_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_FOWNER_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_FSETID_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_KILL_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SETGID_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SETUID_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SETPCAP_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_LINUX_IMMUTABLE_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_NET_BIND_SERVICE_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_NET_BROADCAST_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_NET_ADMIN_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_NET_RAW_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_IPC_LOCK_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_IPC_OWNER_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SYS_MODULE_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SYS_RAWIO_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SYS_CHROOT_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SYS_PTRACE_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SYS_PACCT_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SYS_ADMIN_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SYS_BOOT_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SYS_NICE_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SYS_RESOURCE_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SYS_TIME_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SYS_TTY_CONFIG_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_MKNOD_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_LEASE_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_AUDIT_WRITE_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_AUDIT_CONTROL_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SETFCAP_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_MAC_OVERRIDE_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_MAC_ADMIN_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_SYSLOG_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_WAKE_ALARM_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_BLOCK_SYSPEND_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_AUDIT_READ_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_PERFMON_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_BPF_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

func CAP_CHECKPOINT_RESTORE_handler(s *model.Signal, capType string) *model.Signal {
	return s
}

// downgradeRiskLevel determines whether to downgrade riskLevel for certain capabilities
// according to capType (eff, prm and amb, inh, bnd)
func downgradeRiskLevel(capability uint64, risk int, capType string) int {
	blackList := map[int]bool{
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

	newCapabilitySignal := func(riskLevel int) *model.Signal {
		return &model.Signal{
			Finding: model.Finding{
				Category:        "capabilities",
				RiskLevel:       riskLevel,
				RelativeThreads: []*target.Thread{t},
			},
		}
	}

	// CapEff: most sensitive
	capeff := t.CapEff
	for i := range capCount {
		if (capeff & 1) != 0 {
			// this capability is assigned to current thread
			// raw processing; needs further work in combination (TODO)
			// for example, CAP_NET_ADMIN alone may be HighRisk, but with the
			// main thread sharing net namespace with the host, it should be
			// escalated to Fatal
			signal := newCapabilitySignal(downgradeRiskLevel(capeff&1, capThreatLevels[i], "eff"))
			signal = switchCapabilities(i, signal, "eff")
			signalCapEff = append(signalCapEff, signal)
		}
		// right shift 1 bit to process the next capability
		capeff >>= 1
	}

	// CapPrm and CapAmb: sensitive
	capprm, capamb := t.CapPrm, t.CapAmb
	for i := range capCount {
		if (capprm & 1) != 0 {
			signal := newCapabilitySignal(downgradeRiskLevel(capprm&1, capThreatLevels[i], "prm"))
			signal = switchCapabilities(i, signal, "prm")
			signalCapPrm = append(signalCapPrm, signal)
		}
		if (capamb & 1) != 0 {
			signal := newCapabilitySignal(downgradeRiskLevel(capamb&1, capThreatLevels[i], "amb"))
			signal = switchCapabilities(i, signal, "amb")
			signalCapAmb = append(signalCapAmb, signal)
		}
		capprm >>= 1
		capamb >>= 1
	}

	// CapInh: less sensitive
	capinh := t.CapInh
	for i := range capCount {
		if (capinh & 1) != 0 {
			signal := newCapabilitySignal(downgradeRiskLevel(capinh&1, capThreatLevels[i], "inh"))
			signal = switchCapabilities(i, signal, "inh")
			signalCapInh = append(signalCapInh, signal)
		}
		capinh >>= 1
	}

	// CapBnd: least sensitive
	capbnd := t.CapBnd
	for i := range capCount {
		if (capbnd & 1) != 0 {
			signal := newCapabilitySignal(downgradeRiskLevel(capbnd&1, capThreatLevels[i], "bnd"))
			signal = switchCapabilities(i, signal, "bnd")
			signalCapBnd = append(signalCapBnd, signal)
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

func (r *Rule) AnalyzeCapabilities() {
	// TODO
	// snapshot := r.Snapshot
}

func switchCapabilities(cap int, s *model.Signal, capType string) *model.Signal {
	switch cap {
	case CAP_CHOWN:
		return CAP_CHOWN_handler(s, capType)
	case CAP_DAC_OVERRIDE:
		return CAP_DAC_OVERRIDE_handler(s, capType)
	case CAP_DAC_READ_SEARCH:
		return CAP_DAC_READ_SEARCH_handler(s, capType)
	case CAP_FOWNER:
		return CAP_FOWNER_handler(s, capType)
	case CAP_FSETID:
		return CAP_FSETID_handler(s, capType)
	case CAP_KILL:
		return CAP_KILL_handler(s, capType)
	case CAP_SETGID:
		return CAP_SETGID_handler(s, capType)
	case CAP_SETUID:
		return CAP_SETUID_handler(s, capType)
	case CAP_SETPCAP:
		return CAP_SETPCAP_handler(s, capType)
	case CAP_LINUX_IMMUTABLE:
		return CAP_LINUX_IMMUTABLE_handler(s, capType)
	case CAP_NET_BIND_SERVICE:
		return CAP_NET_BIND_SERVICE_handler(s, capType)
	case CAP_NET_BROADCAST:
		return CAP_NET_BROADCAST_handler(s, capType)
	case CAP_NET_ADMIN:
		return CAP_NET_ADMIN_handler(s, capType)
	case CAP_NET_RAW:
		return CAP_NET_RAW_handler(s, capType)
	case CAP_IPC_LOCK:
		return CAP_IPC_LOCK_handler(s, capType)
	case CAP_IPC_OWNER:
		return CAP_IPC_OWNER_handler(s, capType)
	case CAP_SYS_MODULE:
		return CAP_SYS_MODULE_handler(s, capType)
	case CAP_SYS_RAWIO:
		return CAP_SYS_RAWIO_handler(s, capType)
	case CAP_SYS_CHROOT:
		return CAP_SYS_CHROOT_handler(s, capType)
	case CAP_SYS_PTRACE:
		return CAP_SYS_PTRACE_handler(s, capType)
	case CAP_SYS_PACCT:
		return CAP_SYS_PACCT_handler(s, capType)
	case CAP_SYS_ADMIN:
		return CAP_SYS_ADMIN_handler(s, capType)
	case CAP_SYS_BOOT:
		return CAP_SYS_BOOT_handler(s, capType)
	case CAP_SYS_NICE:
		return CAP_SYS_NICE_handler(s, capType)
	case CAP_SYS_RESOURCE:
		return CAP_SYS_RESOURCE_handler(s, capType)
	case CAP_SYS_TIME:
		return CAP_SYS_TIME_handler(s, capType)
	case CAP_SYS_TTY_CONFIG:
		return CAP_SYS_TTY_CONFIG_handler(s, capType)
	case CAP_MKNOD:
		return CAP_MKNOD_handler(s, capType)
	case CAP_LEASE:
		return CAP_LEASE_handler(s, capType)
	case CAP_AUDIT_WRITE:
		return CAP_AUDIT_WRITE_handler(s, capType)
	case CAP_AUDIT_CONTROL:
		return CAP_AUDIT_CONTROL_handler(s, capType)
	case CAP_SETFCAP:
		return CAP_SETFCAP_handler(s, capType)
	case CAP_MAC_OVERRIDE:
		return CAP_MAC_OVERRIDE_handler(s, capType)
	case CAP_MAC_ADMIN:
		return CAP_MAC_ADMIN_handler(s, capType)
	case CAP_SYSLOG:
		return CAP_SYSLOG_handler(s, capType)
	case CAP_WAKE_ALARM:
		return CAP_WAKE_ALARM_handler(s, capType)
	case CAP_BLOCK_SYSPEND:
		return CAP_BLOCK_SYSPEND_handler(s, capType)
	case CAP_AUDIT_READ:
		return CAP_AUDIT_READ_handler(s, capType)
	case CAP_PERFMON:
		return CAP_PERFMON_handler(s, capType)
	case CAP_BPF:
		return CAP_BPF_handler(s, capType)
	case CAP_CHECKPOINT_RESTORE:
		return CAP_CHECKPOINT_RESTORE_handler(s, capType)
	default:
		return s
	}
}
