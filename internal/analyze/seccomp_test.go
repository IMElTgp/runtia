package analyze

import (
	"reflect"
	"strings"
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

func seccompTestThread() *target.Thread {
	return &target.Thread{
		Tid:          701,
		Tgid:         700,
		Comm:         " seccomp-worker \n",
		IsMainThread: false,
		UserNS:       target.NSRef{Type: "user", Dev: 11, Ino: 111},
		MntNS:        target.NSRef{Type: "mnt", Dev: 22, Ino: 222},
		PIDNS:        target.NSRef{Type: "pid", Dev: 33, Ino: 333},
	}
}

func TestCheckNoNewPrivs(t *testing.T) {
	thread := seccompTestThread()
	thread.NoNewPrivs = false
	thread.SeccompMode = 2
	thread.SeccompFilters = 1

	got := checkNoNewPrivs(thread, []string{"/", "/run"})
	if got == nil {
		t.Fatal("expected no_new_privs signal")
	}
	if got.Category != "seccomp" {
		t.Fatalf("expected seccomp category, got %q", got.Category)
	}
	if got.RiskLevel != Info {
		t.Fatalf("expected info risk, got %d", got.RiskLevel)
	}
	if got.Title != "Thread does not enable no_new_privs" {
		t.Fatalf("unexpected title %q", got.Title)
	}
	if !strings.Contains(got.Summary, "does not enable no_new_privs") {
		t.Fatalf("unexpected summary %q", got.Summary)
	}
	if len(got.Evidence) != 3 {
		t.Fatalf("expected 3 evidence lines, got %#v", got.Evidence)
	}
	if !strings.Contains(got.Evidence[0], `comm="seccomp-worker"`) {
		t.Fatalf("expected trimmed comm in evidence, got %q", got.Evidence[0])
	}
	if !strings.Contains(got.Evidence[1], "NoNewPrivs=false") || !strings.Contains(got.Evidence[1], "SeccompMode=2") || !strings.Contains(got.Evidence[1], "SeccompFilters=1") {
		t.Fatalf("unexpected seccomp evidence %q", got.Evidence[1])
	}
	if !strings.Contains(got.Evidence[2], "userns=user:11:111") || !strings.Contains(got.Evidence[2], "mntns=mnt:22:222") || !strings.Contains(got.Evidence[2], "pidns=pid:33:333") {
		t.Fatalf("unexpected namespace evidence %q", got.Evidence[2])
	}
	if len(got.RelativeThreads) != 1 || got.RelativeThreads[0] != thread {
		t.Fatalf("expected original thread pointer, got %#v", got.RelativeThreads)
	}
	if !reflect.DeepEqual(got.MountPoint, []string{"/", "/run"}) {
		t.Fatalf("expected mount points [\"/\" \"/run\"], got %#v", got.MountPoint)
	}
	if !strings.Contains(got.Recommendation, "Enable no_new_privs") {
		t.Fatalf("unexpected recommendation %q", got.Recommendation)
	}

	thread.NoNewPrivs = true
	if got := checkNoNewPrivs(thread, nil); got != nil {
		t.Fatalf("expected enabled no_new_privs to be ignored, got %#v", got)
	}
}

func TestSwitchSeccompMode(t *testing.T) {
	thread := seccompTestThread()

	thread.SeccompMode = 0
	disabled := switchSeccompMode(thread, []string{"/"})
	if disabled == nil {
		t.Fatal("expected disabled seccomp signal")
	}
	if disabled.Title != "Thread runs without seccomp filtering" {
		t.Fatalf("unexpected disabled title %q", disabled.Title)
	}
	if disabled.RiskLevel != HighRisk {
		t.Fatalf("expected high risk for disabled seccomp, got %d", disabled.RiskLevel)
	}
	if !strings.Contains(disabled.Recommendation, "Keep seccomp enabled in filter mode") {
		t.Fatalf("unexpected recommendation %q", disabled.Recommendation)
	}

	thread.SeccompMode = 1
	strict := switchSeccompMode(thread, []string{"/"})
	if strict == nil {
		t.Fatal("expected strict seccomp signal")
	}
	if strict.Title != "Thread uses strict seccomp mode" {
		t.Fatalf("unexpected strict title %q", strict.Title)
	}
	if strict.RiskLevel != Info {
		t.Fatalf("expected info risk for strict seccomp, got %d", strict.RiskLevel)
	}
	if !strings.Contains(strict.Summary, "very restrictive syscall policy") {
		t.Fatalf("unexpected strict summary %q", strict.Summary)
	}

	thread.SeccompMode = 2
	if got := switchSeccompMode(thread, []string{"/"}); got != nil {
		t.Fatalf("expected filter mode to be ignored, got %#v", got)
	}
}

func TestCheckSeccompModeOnWithoutFilters(t *testing.T) {
	thread := seccompTestThread()
	thread.SeccompMode = 2
	thread.SeccompFilters = 0

	got := checkSeccompModeOnWithoutFilters(thread, []string{"/", "/etc"})
	if got == nil {
		t.Fatal("expected abnormal filter-mode signal")
	}
	if got.Title != "Thread reports seccomp filter mode without attached filters" {
		t.Fatalf("unexpected title %q", got.Title)
	}
	if got.RiskLevel != HighRisk {
		t.Fatalf("expected high risk, got %d", got.RiskLevel)
	}
	if !strings.Contains(got.Summary, "zero attached filters") {
		t.Fatalf("unexpected summary %q", got.Summary)
	}
	if !strings.Contains(got.Recommendation, "Verify that the runtime actually installed seccomp filters") {
		t.Fatalf("unexpected recommendation %q", got.Recommendation)
	}
	if !reflect.DeepEqual(got.MountPoint, []string{"/", "/etc"}) {
		t.Fatalf("expected mount points [\"/\" \"/etc\"], got %#v", got.MountPoint)
	}

	thread.SeccompFilters = 2
	if got := checkSeccompModeOnWithoutFilters(thread, nil); got != nil {
		t.Fatalf("expected nonzero filter count to be ignored, got %#v", got)
	}
	thread.SeccompMode = 0
	thread.SeccompFilters = 0
	if got := checkSeccompModeOnWithoutFilters(thread, nil); got != nil {
		t.Fatalf("expected non-filter mode to be ignored, got %#v", got)
	}
}

func TestAnalyzeSeccompEntryPoint(t *testing.T) {
	ns := target.NSRef{Type: "mnt", Dev: 44, Ino: 55}
	rule := &Rule{
		Snapshot: model.Snapshot{
			MountNamespaces: []model.NamespaceSnapshot{
				{
					NSRef: ns,
					MountInfo: []collect.MountInfo{
						{MountPoint: "/"},
						{MountPoint: "/var/run"},
					},
				},
			},
			Threads: map[int]model.ThreadSnapshot{
				701: model.ThreadSnapshot(target.Thread{
					Tid:            701,
					Tgid:           700,
					Comm:           "no-nnp",
					IsMainThread:   true,
					UserNS:         target.NSRef{Type: "user", Dev: 1, Ino: 2},
					MntNS:          ns,
					PIDNS:          target.NSRef{Type: "pid", Dev: 3, Ino: 4},
					NoNewPrivs:     false,
					SeccompMode:    0,
					SeccompFilters: 0,
				}),
				702: model.ThreadSnapshot(target.Thread{
					Tid:            702,
					Tgid:           700,
					Comm:           "strict-mode",
					UserNS:         target.NSRef{Type: "user", Dev: 1, Ino: 2},
					MntNS:          ns,
					PIDNS:          target.NSRef{Type: "pid", Dev: 3, Ino: 4},
					NoNewPrivs:     true,
					SeccompMode:    1,
					SeccompFilters: 0,
				}),
				703: model.ThreadSnapshot(target.Thread{
					Tid:            703,
					Tgid:           700,
					Comm:           "abnormal-filter",
					UserNS:         target.NSRef{Type: "user", Dev: 1, Ino: 2},
					MntNS:          ns,
					PIDNS:          target.NSRef{Type: "pid", Dev: 3, Ino: 4},
					NoNewPrivs:     true,
					SeccompMode:    2,
					SeccompFilters: 0,
				}),
				704: model.ThreadSnapshot(target.Thread{
					Tid:            704,
					Tgid:           700,
					Comm:           "healthy-filter",
					UserNS:         target.NSRef{Type: "user", Dev: 1, Ino: 2},
					MntNS:          ns,
					PIDNS:          target.NSRef{Type: "pid", Dev: 3, Ino: 4},
					NoNewPrivs:     true,
					SeccompMode:    2,
					SeccompFilters: 3,
				}),
			},
		},
	}

	rule.AnalyzeSeccomp()

	requireRuleSignalCount(t, rule.Signals, 4)

	noNNP := findSignalByTitle(rule.Signals, "Thread does not enable no_new_privs")
	if noNNP == nil {
		t.Fatalf("expected no_new_privs signal in %#v", rule.Signals)
	}
	if noNNP.Category != "seccomp" || noNNP.RiskLevel != Info {
		t.Fatalf("unexpected no_new_privs signal %#v", noNNP)
	}
	if !reflect.DeepEqual(noNNP.MountPoint, []string{"/", "/var/run"}) {
		t.Fatalf("expected mount points [\"/\" \"/var/run\"], got %#v", noNNP.MountPoint)
	}
	if len(noNNP.RelativeThreads) != 1 || noNNP.RelativeThreads[0] == nil || noNNP.RelativeThreads[0].Tid != 701 {
		t.Fatalf("unexpected relative thread %#v", noNNP.RelativeThreads)
	}

	disabled := findSignalByTitle(rule.Signals, "Thread runs without seccomp filtering")
	if disabled == nil || disabled.RiskLevel != HighRisk {
		t.Fatalf("expected disabled seccomp signal, got %#v", disabled)
	}

	strict := findSignalByTitle(rule.Signals, "Thread uses strict seccomp mode")
	if strict == nil || strict.RiskLevel != Info {
		t.Fatalf("expected strict seccomp signal, got %#v", strict)
	}

	abnormal := findSignalByTitle(rule.Signals, "Thread reports seccomp filter mode without attached filters")
	if abnormal == nil || abnormal.RiskLevel != HighRisk {
		t.Fatalf("expected abnormal filter-mode signal, got %#v", abnormal)
	}
	if len(abnormal.RelativeThreads) != 1 || abnormal.RelativeThreads[0] == nil || abnormal.RelativeThreads[0].Tid != 703 {
		t.Fatalf("unexpected abnormal relative thread %#v", abnormal.RelativeThreads)
	}
}
