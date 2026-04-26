package analyze

import (
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

func resetNamespaceAnalyzeCollectorState(t *testing.T) {
	t.Helper()

	oldMntNSThreads := collect.MntNSThreads
	oldPIDNSThreads := collect.PIDNSThreads
	oldUserNSThreads := collect.UserNSThreads
	oldOwnerUserNSByNS := collect.OwnerUserNSByNS
	oldHostMntNS := collect.HostMntNS
	oldHostPIDNS := collect.HostPIDNS
	oldHostUserNS := collect.HostUserNS

	collect.MntNSThreads = make(map[target.NSRef][]*target.Thread)
	collect.PIDNSThreads = make(map[target.NSRef][]*target.Thread)
	collect.UserNSThreads = make(map[target.NSRef][]*target.Thread)
	collect.OwnerUserNSByNS = make(map[target.NSRef]target.NSRef)
	collect.HostMntNS = target.NSRef{}
	collect.HostPIDNS = target.NSRef{}
	collect.HostUserNS = target.NSRef{}

	t.Cleanup(func() {
		collect.MntNSThreads = oldMntNSThreads
		collect.PIDNSThreads = oldPIDNSThreads
		collect.UserNSThreads = oldUserNSThreads
		collect.OwnerUserNSByNS = oldOwnerUserNSByNS
		collect.HostMntNS = oldHostMntNS
		collect.HostPIDNS = oldHostPIDNS
		collect.HostUserNS = oldHostUserNS
	})
}

func TestCheckNamespaceDeviationSignals(t *testing.T) {
	resetNamespaceAnalyzeCollectorState(t)

	userNS := target.NSRef{Type: "user", Dev: 11, Ino: 111}
	pidNS := target.NSRef{Type: "pid", Dev: 22, Ino: 222}
	mntNS := target.NSRef{Type: "mnt", Dev: 33, Ino: 333}
	threadPtr := &target.Thread{
		Tid:          201,
		Tgid:         200,
		Comm:         "ns-worker",
		IsMainThread: false,
		UserNS:       userNS,
		PIDNS:        pidNS,
		MntNS:        mntNS,
	}
	thread := model.ThreadSnapshot(*threadPtr)

	collect.UserNSThreads[userNS] = []*target.Thread{threadPtr}
	collect.PIDNSThreads[pidNS] = []*target.Thread{threadPtr}
	collect.MntNSThreads[mntNS] = []*target.Thread{threadPtr}

	cases := []struct {
		name      string
		check     func(model.ThreadSnapshot) *model.Signal
		wantTitle string
		wantRisk  int
		wantNS    target.NSRef
	}{
		{
			name: "user namespace",
			check: func(thread model.ThreadSnapshot) *model.Signal {
				return checkUserNSDeviation(thread, target.NSRef{Type: "user", Dev: 11, Ino: 112})
			},
			wantTitle: "Thread uses a different user namespace than its main thread",
			wantRisk:  HighRisk,
			wantNS:    userNS,
		},
		{
			name: "pid namespace",
			check: func(thread model.ThreadSnapshot) *model.Signal {
				return checkPIDNSDeviation(thread, target.NSRef{Type: "pid", Dev: 22, Ino: 223})
			},
			wantTitle: "Thread uses a different PID namespace than its main thread",
			wantRisk:  HighRisk,
			wantNS:    pidNS,
		},
		{
			name: "mount namespace",
			check: func(thread model.ThreadSnapshot) *model.Signal {
				return checkMntNSDeviation(thread, target.NSRef{Type: "mnt", Dev: 33, Ino: 334})
			},
			wantTitle: "Thread uses a different mount namespace than its main thread",
			wantRisk:  Info,
			wantNS:    mntNS,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.check(thread)
			if got == nil {
				t.Fatalf("expected signal for %s deviation", tc.name)
			}
			if got.Title != tc.wantTitle {
				t.Fatalf("expected title %q, got %q", tc.wantTitle, got.Title)
			}
			if got.RiskLevel != tc.wantRisk {
				t.Fatalf("expected risk %d, got %d", tc.wantRisk, got.RiskLevel)
			}
			if got.RelativeNS == nil || *got.RelativeNS != tc.wantNS {
				t.Fatalf("expected relative namespace %+v, got %+v", tc.wantNS, got.RelativeNS)
			}
			if len(got.RelativeThreads) != 1 || got.RelativeThreads[0] != threadPtr {
				t.Fatalf("expected relative threads to contain worker thread, got %#v", got.RelativeThreads)
			}
		})
	}

	mainThread := thread
	mainThread.IsMainThread = true
	if got := checkUserNSDeviation(mainThread, target.NSRef{Type: "user", Dev: 11, Ino: 112}); got != nil {
		t.Fatalf("expected main thread user-namespace deviation to be ignored, got %#v", got)
	}
	if got := checkPIDNSDeviation(mainThread, target.NSRef{Type: "pid", Dev: 22, Ino: 223}); got != nil {
		t.Fatalf("expected main thread PID-namespace deviation to be ignored, got %#v", got)
	}
	if got := checkMntNSDeviation(mainThread, target.NSRef{Type: "mnt", Dev: 33, Ino: 334}); got != nil {
		t.Fatalf("expected main thread mount-namespace deviation to be ignored, got %#v", got)
	}
}

func TestCheckNamespaceSharingSignals(t *testing.T) {
	resetNamespaceAnalyzeCollectorState(t)

	userNS := target.NSRef{Type: "user", Dev: 10, Ino: 100}
	pidNS := target.NSRef{Type: "pid", Dev: 20, Ino: 200}
	mntNS := target.NSRef{Type: "mnt", Dev: 30, Ino: 300}
	threadPtr := &target.Thread{
		Tid:          210,
		Tgid:         210,
		Comm:         "share-check",
		IsMainThread: true,
		UserNS:       userNS,
		PIDNS:        pidNS,
		MntNS:        mntNS,
	}
	thread := model.ThreadSnapshot(*threadPtr)

	collect.UserNSThreads[userNS] = []*target.Thread{threadPtr}
	collect.PIDNSThreads[pidNS] = []*target.Thread{threadPtr}
	collect.MntNSThreads[mntNS] = []*target.Thread{threadPtr}

	cases := []struct {
		name      string
		setupHost func()
		check     func(model.ThreadSnapshot) *model.Signal
		wantTitle string
		wantRisk  int
		wantNS    target.NSRef
	}{
		{
			name: "user namespace shares host",
			setupHost: func() {
				collect.HostUserNS = userNS
			},
			check:     checkUserNamespaceSharing,
			wantTitle: "Thread shares the host user namespace",
			wantRisk:  Fatal,
			wantNS:    userNS,
		},
		{
			name: "pid namespace shares host",
			setupHost: func() {
				collect.HostPIDNS = pidNS
			},
			check:     checkPIDNamespaceSharing,
			wantTitle: "Thread shares the host PID namespace",
			wantRisk:  HighRisk,
			wantNS:    pidNS,
		},
		{
			name: "mount namespace shares host",
			setupHost: func() {
				collect.HostMntNS = mntNS
			},
			check:     checkMntNamespaceSharing,
			wantTitle: "Thread shares the host mount namespace",
			wantRisk:  HighRisk,
			wantNS:    mntNS,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			collect.HostUserNS = target.NSRef{}
			collect.HostPIDNS = target.NSRef{}
			collect.HostMntNS = target.NSRef{}
			tc.setupHost()

			got := tc.check(thread)
			if got == nil {
				t.Fatalf("expected signal for %s", tc.name)
			}
			if got.Title != tc.wantTitle {
				t.Fatalf("expected title %q, got %q", tc.wantTitle, got.Title)
			}
			if got.RiskLevel != tc.wantRisk {
				t.Fatalf("expected risk %d, got %d", tc.wantRisk, got.RiskLevel)
			}
			if got.RelativeNS == nil || *got.RelativeNS != tc.wantNS {
				t.Fatalf("expected relative namespace %+v, got %+v", tc.wantNS, got.RelativeNS)
			}
			if len(got.RelativeThreads) != 1 || got.RelativeThreads[0] != threadPtr {
				t.Fatalf("expected relative threads to contain thread, got %#v", got.RelativeThreads)
			}
		})
	}

	collect.HostUserNS = target.NSRef{Type: "user", Dev: 10, Ino: 101}
	if got := checkUserNamespaceSharing(thread); got != nil {
		t.Fatalf("expected no signal when user namespace differs from host, got %#v", got)
	}
	collect.HostPIDNS = target.NSRef{Type: "pid", Dev: 20, Ino: 201}
	if got := checkPIDNamespaceSharing(thread); got != nil {
		t.Fatalf("expected no signal when PID namespace differs from host, got %#v", got)
	}
	collect.HostMntNS = target.NSRef{Type: "mnt", Dev: 30, Ino: 301}
	if got := checkMntNamespaceSharing(thread); got != nil {
		t.Fatalf("expected no signal when mount namespace differs from host, got %#v", got)
	}
}

func TestCheckNamespaceDeviationReturnsNilForMatchingNamespace(t *testing.T) {
	resetNamespaceAnalyzeCollectorState(t)

	userNS := target.NSRef{Type: "user", Dev: 15, Ino: 150}
	pidNS := target.NSRef{Type: "pid", Dev: 25, Ino: 250}
	mntNS := target.NSRef{Type: "mnt", Dev: 35, Ino: 350}
	thread := model.ThreadSnapshot(target.Thread{
		Tid:          211,
		Tgid:         210,
		Comm:         "same-ns",
		IsMainThread: false,
		UserNS:       userNS,
		PIDNS:        pidNS,
		MntNS:        mntNS,
	})

	if got := checkUserNSDeviation(thread, userNS); got != nil {
		t.Fatalf("expected nil user-namespace deviation signal for matching namespace, got %#v", got)
	}
	if got := checkPIDNSDeviation(thread, pidNS); got != nil {
		t.Fatalf("expected nil PID-namespace deviation signal for matching namespace, got %#v", got)
	}
	if got := checkMntNSDeviation(thread, mntNS); got != nil {
		t.Fatalf("expected nil mount-namespace deviation signal for matching namespace, got %#v", got)
	}
}

func TestCheckOwnerUserNSExistence(t *testing.T) {
	resetNamespaceAnalyzeCollectorState(t)

	pidNS := target.NSRef{Type: "pid", Dev: 44, Ino: 444}
	mntNS := target.NSRef{Type: "mnt", Dev: 55, Ino: 555}
	threadPtr := &target.Thread{
		Tid:    301,
		Tgid:   300,
		Comm:   "owner-check",
		PIDNS:  pidNS,
		MntNS:  mntNS,
		UserNS: target.NSRef{Type: "user", Dev: 66, Ino: 666},
	}
	thread := model.ThreadSnapshot(*threadPtr)

	collect.PIDNSThreads[pidNS] = []*target.Thread{threadPtr}
	collect.MntNSThreads[mntNS] = []*target.Thread{threadPtr}

	cases := []struct {
		name      string
		ns        target.NSRef
		wantTitle string
	}{
		{
			name:      "pid namespace owner missing",
			ns:        pidNS,
			wantTitle: "Could not resolve the owner user namespace of the thread's PID namespace",
		},
		{
			name:      "mount namespace owner missing",
			ns:        mntNS,
			wantTitle: "Could not resolve the owner user namespace of the thread's mount namespace",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkOwnerUserNSExistence(thread, tc.ns)
			if got == nil {
				t.Fatalf("expected signal for %s", tc.name)
			}
			if got.Title != tc.wantTitle {
				t.Fatalf("expected title %q, got %q", tc.wantTitle, got.Title)
			}
			if got.RelativeNS == nil || *got.RelativeNS != tc.ns {
				t.Fatalf("expected relative namespace %+v, got %+v", tc.ns, got.RelativeNS)
			}
		})
	}

	collect.OwnerUserNSByNS[pidNS] = target.NSRef{Type: "user", Dev: 77, Ino: 777}
	if got := checkOwnerUserNSExistence(thread, pidNS); got != nil {
		t.Fatalf("expected no owner-existence signal when owner is known, got %#v", got)
	}
}

func TestCheckOwnerUserNSExistenceCornerCases(t *testing.T) {
	resetNamespaceAnalyzeCollectorState(t)

	thread := model.ThreadSnapshot(target.Thread{Tid: 302, Tgid: 300, Comm: "owner-corners"})

	if got := checkOwnerUserNSExistence(thread, target.NSRef{}); got != nil {
		t.Fatalf("expected nil signal for empty namespace reference, got %#v", got)
	}

	netNS := target.NSRef{Type: "net", Dev: 46, Ino: 446}
	got := checkOwnerUserNSExistence(thread, netNS)
	if got == nil {
		t.Fatalf("expected signal for generic namespace type")
	}
	if got.Title != "Could not resolve the owner user namespace of the thread's net namespace" {
		t.Fatalf("unexpected title %q", got.Title)
	}
	if got.RelativeNS == nil || *got.RelativeNS != netNS {
		t.Fatalf("expected relative namespace %+v, got %+v", netNS, got.RelativeNS)
	}
}

func TestCheckOwnerDeviation(t *testing.T) {
	resetNamespaceAnalyzeCollectorState(t)

	userNS := target.NSRef{Type: "user", Dev: 88, Ino: 888}
	otherUserNS := target.NSRef{Type: "user", Dev: 89, Ino: 889}
	pidNS := target.NSRef{Type: "pid", Dev: 90, Ino: 900}
	mntNS := target.NSRef{Type: "mnt", Dev: 91, Ino: 901}
	threadPtr := &target.Thread{
		Tid:    401,
		Tgid:   400,
		Comm:   "owner-drift",
		UserNS: userNS,
		PIDNS:  pidNS,
		MntNS:  mntNS,
	}
	thread := model.ThreadSnapshot(*threadPtr)

	collect.PIDNSThreads[pidNS] = []*target.Thread{threadPtr}
	collect.MntNSThreads[mntNS] = []*target.Thread{threadPtr}
	collect.OwnerUserNSByNS[pidNS] = otherUserNS
	collect.OwnerUserNSByNS[mntNS] = userNS

	got := checkOwnerDeviation(thread, pidNS, userNS)
	if got == nil {
		t.Fatalf("expected PID owner deviation signal")
	}
	if got.Title != "Thread's PID namespace is owned by a different user namespace" {
		t.Fatalf("unexpected title %q", got.Title)
	}
	if got.RiskLevel != HighRisk {
		t.Fatalf("expected HighRisk, got %d", got.RiskLevel)
	}
	if got.RelativeNS == nil || *got.RelativeNS != pidNS {
		t.Fatalf("expected relative namespace %+v, got %+v", pidNS, got.RelativeNS)
	}

	if got := checkOwnerDeviation(thread, mntNS, userNS); got != nil {
		t.Fatalf("expected no mount owner deviation when owner matches thread user namespace, got %#v", got)
	}
	if got := checkOwnerDeviation(thread, target.NSRef{Type: "pid", Dev: 99, Ino: 999}, userNS); got != nil {
		t.Fatalf("expected no signal when owner is unknown here, got %#v", got)
	}
}

func TestCheckOwnerDeviationCornerCases(t *testing.T) {
	resetNamespaceAnalyzeCollectorState(t)

	userNS := target.NSRef{Type: "user", Dev: 98, Ino: 998}
	thread := model.ThreadSnapshot(target.Thread{
		Tid:    402,
		Tgid:   400,
		Comm:   "owner-corner",
		UserNS: userNS,
	})

	if got := checkOwnerDeviation(thread, target.NSRef{}, userNS); got != nil {
		t.Fatalf("expected nil signal for empty namespace reference, got %#v", got)
	}

	netNS := target.NSRef{Type: "net", Dev: 92, Ino: 902}
	ownerUserNS := target.NSRef{Type: "user", Dev: 93, Ino: 903}
	collect.OwnerUserNSByNS[netNS] = ownerUserNS

	got := checkOwnerDeviation(thread, netNS, userNS)
	if got == nil {
		t.Fatalf("expected owner deviation signal for generic namespace type")
	}
	if got.Title != "Thread's net namespace is owned by a different user namespace" {
		t.Fatalf("unexpected title %q", got.Title)
	}
	if got.RelativeNS == nil || *got.RelativeNS != netNS {
		t.Fatalf("expected relative namespace %+v, got %+v", netNS, got.RelativeNS)
	}
}

func TestAnalyzeNamespacesUsesPerNamespaceOwnerChecks(t *testing.T) {
	resetNamespaceAnalyzeCollectorState(t)

	mainUserNS := target.NSRef{Type: "user", Dev: 100, Ino: 1000}
	workerUserNS := target.NSRef{Type: "user", Dev: 101, Ino: 1001}
	otherOwnerUserNS := target.NSRef{Type: "user", Dev: 102, Ino: 1002}
	mainPIDNS := target.NSRef{Type: "pid", Dev: 110, Ino: 1100}
	workerPIDNS := target.NSRef{Type: "pid", Dev: 111, Ino: 1101}
	mainMntNS := target.NSRef{Type: "mnt", Dev: 120, Ino: 1200}
	workerMntNS := target.NSRef{Type: "mnt", Dev: 121, Ino: 1201}

	mainThreadPtr := &target.Thread{
		Tid:          500,
		Tgid:         500,
		Comm:         "entry",
		IsMainThread: true,
		UserNS:       mainUserNS,
		PIDNS:        mainPIDNS,
		MntNS:        mainMntNS,
	}
	workerThreadPtr := &target.Thread{
		Tid:          501,
		Tgid:         500,
		Comm:         "worker",
		IsMainThread: false,
		UserNS:       workerUserNS,
		PIDNS:        workerPIDNS,
		MntNS:        workerMntNS,
	}

	collect.UserNSThreads[mainUserNS] = []*target.Thread{mainThreadPtr}
	collect.UserNSThreads[workerUserNS] = []*target.Thread{workerThreadPtr}
	collect.PIDNSThreads[mainPIDNS] = []*target.Thread{mainThreadPtr}
	collect.PIDNSThreads[workerPIDNS] = []*target.Thread{workerThreadPtr}
	collect.MntNSThreads[mainMntNS] = []*target.Thread{mainThreadPtr}
	collect.MntNSThreads[workerMntNS] = []*target.Thread{workerThreadPtr}
	collect.OwnerUserNSByNS[mainPIDNS] = mainUserNS
	collect.OwnerUserNSByNS[mainMntNS] = mainUserNS
	collect.OwnerUserNSByNS[workerMntNS] = otherOwnerUserNS
	collect.HostUserNS = target.NSRef{Type: "user", Dev: 200, Ino: 2000}
	collect.HostPIDNS = target.NSRef{Type: "pid", Dev: 201, Ino: 2001}
	collect.HostMntNS = target.NSRef{Type: "mnt", Dev: 202, Ino: 2002}

	rule := Rule{
		Snapshot: model.Snapshot{
			Threads: map[int]model.ThreadSnapshot{
				mainThreadPtr.Tid:   model.ThreadSnapshot(*mainThreadPtr),
				workerThreadPtr.Tid: model.ThreadSnapshot(*workerThreadPtr),
			},
		},
	}

	rule.AnalyzeNamespaces()

	if got := countSignalsByTitle(rule.Signals, "Could not resolve the owner user namespace of the thread's PID namespace"); got != 1 {
		t.Fatalf("expected one PID owner-unknown signal, got %d", got)
	}
	if got := countSignalsByTitle(rule.Signals, "Thread's mount namespace is owned by a different user namespace"); got != 1 {
		t.Fatalf("expected one mount owner-deviation signal, got %d", got)
	}
	if got := countSignalsByTitle(rule.Signals, "Could not resolve the owner user namespace of the thread's mount namespace"); got != 0 {
		t.Fatalf("expected no mount owner-unknown signals, got %d", got)
	}
	if got := countSignalsByTitle(rule.Signals, "Thread's PID namespace is owned by a different user namespace"); got != 0 {
		t.Fatalf("expected no PID owner-deviation signals when owner is unknown, got %d", got)
	}
}

func TestAnalyzeNamespacesWithMissingMainThreadSkipsDeviationChecks(t *testing.T) {
	resetNamespaceAnalyzeCollectorState(t)

	userNS := target.NSRef{Type: "user", Dev: 301, Ino: 3001}
	pidNS := target.NSRef{Type: "pid", Dev: 302, Ino: 3002}
	mntNS := target.NSRef{Type: "mnt", Dev: 303, Ino: 3003}
	threadPtr := &target.Thread{
		Tid:          601,
		Tgid:         600,
		Comm:         "orphan-worker",
		IsMainThread: false,
		UserNS:       userNS,
		PIDNS:        pidNS,
		MntNS:        mntNS,
	}

	collect.UserNSThreads[userNS] = []*target.Thread{threadPtr}
	collect.PIDNSThreads[pidNS] = []*target.Thread{threadPtr}
	collect.MntNSThreads[mntNS] = []*target.Thread{threadPtr}
	collect.HostUserNS = userNS
	collect.OwnerUserNSByNS[mntNS] = userNS

	rule := Rule{
		Snapshot: model.Snapshot{
			Threads: map[int]model.ThreadSnapshot{
				threadPtr.Tid: model.ThreadSnapshot(*threadPtr),
			},
		},
	}

	rule.AnalyzeNamespaces()

	if got := countSignalsByTitle(rule.Signals, "Thread shares the host user namespace"); got != 1 {
		t.Fatalf("expected one host user-namespace sharing signal, got %d", got)
	}
	if got := countSignalsByTitle(rule.Signals, "Could not resolve the owner user namespace of the thread's PID namespace"); got != 1 {
		t.Fatalf("expected one PID owner-unknown signal, got %d", got)
	}
	if got := countSignalsByTitle(rule.Signals, "Thread uses a different user namespace than its main thread"); got != 0 {
		t.Fatalf("expected no user-namespace deviation signal without main thread snapshot, got %d", got)
	}
	if got := countSignalsByTitle(rule.Signals, "Thread uses a different PID namespace than its main thread"); got != 0 {
		t.Fatalf("expected no PID-namespace deviation signal without main thread snapshot, got %d", got)
	}
	if got := countSignalsByTitle(rule.Signals, "Thread uses a different mount namespace than its main thread"); got != 0 {
		t.Fatalf("expected no mount-namespace deviation signal without main thread snapshot, got %d", got)
	}
}
