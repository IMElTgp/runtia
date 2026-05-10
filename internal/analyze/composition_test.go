package analyze

import (
	"reflect"
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

func compositionThread(tid, tgid int) *target.Thread {
	return &target.Thread{
		Tid:          tid,
		Tgid:         tgid,
		Comm:         "composition-thread",
		IsMainThread: tid == tgid,
		UserNS:       target.NSRef{Type: "user", Dev: uint64(tid + 1), Ino: uint64(tid + 101)},
		MntNS:        target.NSRef{Type: "mnt", Dev: uint64(tid + 2), Ino: uint64(tid + 102)},
		PIDNS:        target.NSRef{Type: "pid", Dev: uint64(tid + 3), Ino: uint64(tid + 103)},
		SeccompMode:  0,
	}
}

func capabilitySignal(thread *target.Thread, risk int, capName, capSet string) model.Signal {
	return model.Signal{
		Finding: model.Finding{
			Category:        "capabilities",
			RiskLevel:       risk,
			Title:           "Thread has " + capName + " in its " + capSet + " capability set",
			RelativeThreads: []*target.Thread{thread},
		},
	}
}

func namespaceSignal(thread *target.Thread, risk int, title string, ns target.NSRef) model.Signal {
	return model.Signal{
		Finding: model.Finding{
			Category:        "namespace",
			RiskLevel:       risk,
			Title:           title,
			RelativeThreads: []*target.Thread{thread},
			RelativeNS:      &ns,
		},
	}
}

func mountSignal(thread *target.Thread, risk int, title string, mountPoint string) model.Signal {
	ns := thread.MntNS
	return model.Signal{
		Finding: model.Finding{
			Category:        "mount",
			RiskLevel:       risk,
			Title:           title,
			RelativeThreads: []*target.Thread{thread},
			RelativeNS:      &ns,
			MountPoint:      []string{mountPoint},
		},
	}
}

func seccompSignal(thread *target.Thread, risk int, title string) model.Signal {
	return model.Signal{
		Finding: model.Finding{
			Category:        "seccomp",
			RiskLevel:       risk,
			Title:           title,
			RelativeThreads: []*target.Thread{thread},
		},
	}
}

func TestAnalyzeCompositionCAPSysPtraceHostPIDNamespace(t *testing.T) {
	thread := compositionThread(100, 100)
	rule := &Rule{
		Signals: []model.Signal{
			capabilitySignal(thread, Fatal, "CAP_SYS_PTRACE", "effective"),
			namespaceSignal(thread, HighRisk, "Thread shares the host PID namespace", thread.PIDNS),
		},
	}

	rule.AnalyzeComposition()

	if !rule.Signals[0].Covered || !rule.Signals[1].Covered {
		t.Fatalf("expected primitive signals to be marked covered: %#v", rule.Signals[:2])
	}
	got := findSignalByTitle(rule.Signals, "CAP_SYS_PTRACE combined with host PID namespace")
	if got == nil {
		t.Fatalf("expected composition signal in %#v", rule.Signals)
	}
	if got.Category != "composition" || got.RiskLevel != Fatal {
		t.Fatalf("unexpected composition signal %#v", got)
	}
	if got.RelativeNS == nil || *got.RelativeNS != thread.PIDNS {
		t.Fatalf("expected related PID namespace %+v, got %+v", thread.PIDNS, got.RelativeNS)
	}
	if len(got.RelativeThreads) != 1 || got.RelativeThreads[0] != thread {
		t.Fatalf("expected related thread %p, got %#v", thread, got.RelativeThreads)
	}
}

func TestAnalyzeCompositionCAPSysAdminNonPrivateMountPropagationAggregatesMountPoints(t *testing.T) {
	thread := compositionThread(200, 200)
	rule := &Rule{
		Signals: []model.Signal{
			capabilitySignal(thread, Fatal, "CAP_SYS_ADMIN", "effective"),
			mountSignal(thread, HighRisk, "Mount point with non-private status in mount tree", "/lab/shared"),
			mountSignal(thread, HighRisk, "Mount point with non-private status in mount tree", "/lab/shared-two"),
		},
	}

	rule.AnalyzeComposition()

	for i := 0; i < 3; i++ {
		if !rule.Signals[i].Covered {
			t.Fatalf("expected primitive signal %d to be covered", i)
		}
	}
	got := findSignalByTitle(rule.Signals, "CAP_SYS_ADMIN combined with non-private mount propagation")
	if got == nil {
		t.Fatalf("expected composition signal in %#v", rule.Signals)
	}
	if got.Category != "composition" || got.RiskLevel != Fatal {
		t.Fatalf("unexpected composition signal %#v", got)
	}
	if want := []string{"/lab/shared", "/lab/shared-two"}; !reflect.DeepEqual(got.MountPoint, want) {
		t.Fatalf("expected mount points %v, got %#v", want, got.MountPoint)
	}
	if got.RelativeNS == nil || *got.RelativeNS != thread.MntNS {
		t.Fatalf("expected related mount namespace %+v, got %+v", thread.MntNS, got.RelativeNS)
	}
}

func TestAnalyzeCompositionCAPDACOverrideWritableHostOrSensitiveMount(t *testing.T) {
	thread := compositionThread(300, 300)
	rule := &Rule{
		Signals: []model.Signal{
			capabilitySignal(thread, Fatal, "CAP_DAC_OVERRIDE", "effective"),
			mountSignal(thread, HighRisk, "Host filesystem view /host is writable", "/host"),
			mountSignal(thread, MediumRisk, "Sensitive runtime path /etc is writable", "/etc"),
			mountSignal(thread, MediumRisk, "Sensitive runtime path /dev is writable", "/dev"),
		},
	}

	rule.AnalyzeComposition()

	if !rule.Signals[0].Covered || !rule.Signals[1].Covered || !rule.Signals[2].Covered {
		t.Fatalf("expected CAP_DAC_OVERRIDE and matched mount signals to be covered")
	}
	if rule.Signals[3].Covered {
		t.Fatalf("did not expect /dev mount signal to be covered by CAP_DAC_OVERRIDE composition")
	}
	got := findSignalByTitle(rule.Signals, "CAP_DAC_OVERRIDE combined with writable host or sensitive mount")
	if got == nil {
		t.Fatalf("expected composition signal in %#v", rule.Signals)
	}
	if got.RiskLevel != Fatal {
		t.Fatalf("expected fatal composition risk, got %d", got.RiskLevel)
	}
	if want := []string{"/etc", "/host"}; !reflect.DeepEqual(got.MountPoint, want) {
		t.Fatalf("expected mount points %v, got %#v", want, got.MountPoint)
	}
}

func TestAnalyzeCompositionUnconfinedSeccompHighRiskCapabilityUsesHighestCapabilityRisk(t *testing.T) {
	thread := compositionThread(400, 400)
	rule := &Rule{
		Signals: []model.Signal{
			seccompSignal(thread, HighRisk, "Thread runs without seccomp filtering"),
			capabilitySignal(thread, HighRisk, "CAP_NET_RAW", "effective"),
			capabilitySignal(thread, Fatal, "CAP_SYS_ADMIN", "effective"),
		},
	}

	rule.AnalyzeComposition()

	if !rule.Signals[0].Covered || !rule.Signals[1].Covered || !rule.Signals[2].Covered {
		t.Fatalf("expected seccomp and high-risk capability signals to be covered")
	}
	got := findSignalByTitle(rule.Signals, "Unconfined seccomp combined with high-risk capability")
	if got == nil {
		t.Fatalf("expected composition signal in %#v", rule.Signals)
	}
	if got.RiskLevel != Fatal {
		t.Fatalf("expected fatal composition risk due to CAP_SYS_ADMIN, got %d", got.RiskLevel)
	}
	if len(got.RelativeThreads) != 1 || got.RelativeThreads[0] != thread {
		t.Fatalf("expected related thread %p, got %#v", thread, got.RelativeThreads)
	}
}

func TestAnalyzeCompositionNoNewPrivsDelayedPrivilegeTransitionCapability(t *testing.T) {
	thread := compositionThread(500, 500)
	rule := &Rule{
		Signals: []model.Signal{
			seccompSignal(thread, Info, "Thread does not enable no_new_privs"),
			capabilitySignal(thread, LowRisk, "CAP_SETUID", "permitted"),
			capabilitySignal(thread, HighRisk, "CAP_SETFCAP", "ambient"),
			capabilitySignal(thread, MediumRisk, "CAP_SETUID", "effective"),
		},
	}

	rule.AnalyzeComposition()

	if !rule.Signals[0].Covered || !rule.Signals[1].Covered || !rule.Signals[2].Covered {
		t.Fatalf("expected no_new_privs and delayed privilege-transition capability signals to be covered")
	}
	if rule.Signals[3].Covered {
		t.Fatalf("did not expect effective CAP_SETUID to be covered by delayed-transition composition")
	}

	got := findSignalByTitle(rule.Signals, "NoNewPrivs disabled combined with delayed privilege-transition capability")
	if got == nil {
		t.Fatalf("expected composition signal in %#v", rule.Signals)
	}
	if got.RiskLevel != HighRisk {
		t.Fatalf("expected high-risk composition, got %d", got.RiskLevel)
	}
	if len(got.RelativeThreads) != 1 || got.RelativeThreads[0] != thread {
		t.Fatalf("expected related thread %p, got %#v", thread, got.RelativeThreads)
	}
}

func TestAnalyzeCompositionCAPSysChrootMountNamespaceDeviation(t *testing.T) {
	thread := compositionThread(600, 601)
	rule := &Rule{
		Signals: []model.Signal{
			capabilitySignal(thread, MediumRisk, "CAP_SYS_CHROOT", "effective"),
			namespaceSignal(thread, Info, "Thread uses a different mount namespace than its main thread", thread.MntNS),
		},
	}

	rule.AnalyzeComposition()

	if !rule.Signals[0].Covered || !rule.Signals[1].Covered {
		t.Fatalf("expected CAP_SYS_CHROOT and mount-namespace deviation signals to be covered")
	}

	got := findSignalByTitle(rule.Signals, "CAP_SYS_CHROOT combined with thread-level mount namespace deviation")
	if got == nil {
		t.Fatalf("expected composition signal in %#v", rule.Signals)
	}
	if got.RiskLevel != HighRisk {
		t.Fatalf("expected high-risk composition, got %d", got.RiskLevel)
	}
	if got.RelativeNS == nil || *got.RelativeNS != thread.MntNS {
		t.Fatalf("expected related mount namespace %+v, got %+v", thread.MntNS, got.RelativeNS)
	}
}

func TestAnalyzeCompositionCAPKillHostPIDNamespace(t *testing.T) {
	thread := compositionThread(700, 700)
	rule := &Rule{
		Signals: []model.Signal{
			capabilitySignal(thread, LowRisk, "CAP_KILL", "effective"),
			namespaceSignal(thread, HighRisk, "Thread shares the host PID namespace", thread.PIDNS),
		},
	}

	rule.AnalyzeComposition()

	if !rule.Signals[0].Covered || !rule.Signals[1].Covered {
		t.Fatalf("expected CAP_KILL and host PID namespace signals to be covered")
	}

	got := findSignalByTitle(rule.Signals, "CAP_KILL combined with host PID namespace")
	if got == nil {
		t.Fatalf("expected composition signal in %#v", rule.Signals)
	}
	if got.RiskLevel != Fatal {
		t.Fatalf("expected fatal composition, got %d", got.RiskLevel)
	}
	if got.RelativeNS == nil || *got.RelativeNS != thread.PIDNS {
		t.Fatalf("expected related PID namespace %+v, got %+v", thread.PIDNS, got.RelativeNS)
	}
}
