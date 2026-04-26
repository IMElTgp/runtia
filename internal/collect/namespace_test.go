package collect

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/target"
	"golang.org/x/sys/unix"
)

func statNSRef(t *testing.T, path, nsType string) target.NSRef {
	t.Helper()

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer unix.Close(fd)

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatalf("fstat %s: %v", path, err)
	}

	return target.NSRef{
		Type: nsType,
		Dev:  st.Dev,
		Ino:  st.Ino,
	}
}

func resetNamespaceCollectorState(t *testing.T) {
	t.Helper()

	oldMntNSThreads := MntNSThreads
	oldPIDNSThreads := PIDNSThreads
	oldUserNSThreads := UserNSThreads
	oldMntNSInfo := MntNSInfo
	oldOwnerUserNSByNS := OwnerUserNSByNS
	oldHostMntNS := HostMntNS
	oldHostPIDNS := HostPIDNS
	oldHostUserNS := HostUserNS

	MntNSThreads = make(map[target.NSRef][]*target.Thread)
	PIDNSThreads = make(map[target.NSRef][]*target.Thread)
	UserNSThreads = make(map[target.NSRef][]*target.Thread)
	MntNSInfo = make(map[target.NSRef][]MountInfo)
	OwnerUserNSByNS = make(map[target.NSRef]target.NSRef)
	HostMntNS = target.NSRef{}
	HostPIDNS = target.NSRef{}
	HostUserNS = target.NSRef{}

	t.Cleanup(func() {
		MntNSThreads = oldMntNSThreads
		PIDNSThreads = oldPIDNSThreads
		UserNSThreads = oldUserNSThreads
		MntNSInfo = oldMntNSInfo
		OwnerUserNSByNS = oldOwnerUserNSByNS
		HostMntNS = oldHostMntNS
		HostPIDNS = oldHostPIDNS
		HostUserNS = oldHostUserNS
	})
}

func TestClctHostNamespaceMatchesProcSelfNamespaceFiles(t *testing.T) {
	resetNamespaceCollectorState(t)

	if err := ClctHostNamespace(); err != nil {
		t.Fatalf("ClctHostNamespace() error = %v", err)
	}

	if HostMntNS != statNSRef(t, filepath.Join("/proc/self/ns", "mnt"), "mnt") {
		t.Fatalf("unexpected host mount namespace: got %+v", HostMntNS)
	}
	if HostPIDNS != statNSRef(t, filepath.Join("/proc/self/ns", "pid"), "pid") {
		t.Fatalf("unexpected host pid namespace: got %+v", HostPIDNS)
	}
	if HostUserNS != statNSRef(t, filepath.Join("/proc/self/ns", "user"), "user") {
		t.Fatalf("unexpected host user namespace: got %+v", HostUserNS)
	}
}

func TestClctHostNamespaceMatchesCurrentThreadNamespaces(t *testing.T) {
	resetNamespaceCollectorState(t)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tid := unix.Gettid()
	pid := os.Getpid()
	thread := &target.Thread{
		Tid:          tid,
		Tgid:         pid,
		IsMainThread: tid == pid,
	}

	if err := ClctHostNamespace(); err != nil {
		t.Fatalf("ClctHostNamespace() error = %v", err)
	}
	if err := ClctNamespace(thread); err != nil {
		t.Fatalf("ClctNamespace() error = %v", err)
	}

	if thread.MntNS != HostMntNS {
		t.Fatalf("thread mount namespace %+v does not match collected host namespace %+v", thread.MntNS, HostMntNS)
	}
	if thread.PIDNS != HostPIDNS {
		t.Fatalf("thread pid namespace %+v does not match collected host namespace %+v", thread.PIDNS, HostPIDNS)
	}
	if thread.UserNS != HostUserNS {
		t.Fatalf("thread user namespace %+v does not match collected host namespace %+v", thread.UserNS, HostUserNS)
	}

	if got := ThreadsForNS(thread.MntNS); len(got) != 1 || got[0] != thread {
		t.Fatalf("expected current thread to be tracked in mount namespace, got %#v", got)
	}
	if got := ThreadsForNS(thread.PIDNS); len(got) != 1 || got[0] != thread {
		t.Fatalf("expected current thread to be tracked in pid namespace, got %#v", got)
	}
	if got := ThreadsForNS(thread.UserNS); len(got) != 1 || got[0] != thread {
		t.Fatalf("expected current thread to be tracked in user namespace, got %#v", got)
	}

	if owner := GetOwnerUserNS(thread.MntNS); owner != thread.UserNS {
		t.Fatalf("expected mount namespace owner %+v to match thread user namespace %+v", owner, thread.UserNS)
	}
	if owner := GetOwnerUserNS(thread.PIDNS); owner != thread.UserNS {
		t.Fatalf("expected pid namespace owner %+v to match thread user namespace %+v", owner, thread.UserNS)
	}
}

func TestThreadsForNSDispatchAndCopy(t *testing.T) {
	resetNamespaceCollectorState(t)

	mntNS := target.NSRef{Type: "mnt", Dev: 11, Ino: 111}
	pidNS := target.NSRef{Type: "pid", Dev: 22, Ino: 222}
	userNS := target.NSRef{Type: "user", Dev: 33, Ino: 333}

	mntThread := &target.Thread{Tid: 1, Tgid: 1, MntNS: mntNS}
	pidThread := &target.Thread{Tid: 2, Tgid: 2, PIDNS: pidNS}
	userThread := &target.Thread{Tid: 3, Tgid: 3, UserNS: userNS}

	MntNSThreads[mntNS] = []*target.Thread{mntThread}
	PIDNSThreads[pidNS] = []*target.Thread{pidThread}
	UserNSThreads[userNS] = []*target.Thread{userThread}

	cases := []struct {
		name    string
		ns      target.NSRef
		wantTid int
	}{
		{
			name:    "mount namespace",
			ns:      mntNS,
			wantTid: mntThread.Tid,
		},
		{
			name:    "pid namespace",
			ns:      pidNS,
			wantTid: pidThread.Tid,
		},
		{
			name:    "user namespace",
			ns:      userNS,
			wantTid: userThread.Tid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ThreadsForNS(tc.ns)
			if len(got) != 1 || got[0] == nil || got[0].Tid != tc.wantTid {
				t.Fatalf("expected one thread with tid=%d, got %#v", tc.wantTid, got)
			}

			got[0] = nil
			again := ThreadsForNS(tc.ns)
			if len(again) != 1 || again[0] == nil || again[0].Tid != tc.wantTid {
				t.Fatalf("expected returned slice mutation not to affect stored threads, got %#v", again)
			}
		})
	}

	if got := ThreadsForNS(target.NSRef{Type: "net", Dev: 44, Ino: 444}); got != nil {
		t.Fatalf("expected nil for unsupported namespace type, got %#v", got)
	}
}

func TestGetOwnerUserNSKnownAndUnknown(t *testing.T) {
	resetNamespaceCollectorState(t)

	pidNS := target.NSRef{Type: "pid", Dev: 55, Ino: 555}
	ownerUserNS := target.NSRef{Type: "user", Dev: 66, Ino: 666}
	OwnerUserNSByNS[pidNS] = ownerUserNS

	if got := GetOwnerUserNS(pidNS); got != ownerUserNS {
		t.Fatalf("expected owner user namespace %+v, got %+v", ownerUserNS, got)
	}

	if got := GetOwnerUserNS(target.NSRef{Type: "mnt", Dev: 77, Ino: 777}); got != (target.NSRef{}) {
		t.Fatalf("expected zero-value namespace for unknown owner, got %+v", got)
	}
}

func TestClctNamespaceReturnsErrorForMissingThread(t *testing.T) {
	resetNamespaceCollectorState(t)

	thread := &target.Thread{
		Tid:          -1,
		Tgid:         -1,
		IsMainThread: true,
	}

	if err := ClctNamespace(thread); err == nil {
		t.Fatalf("expected error for non-existent /proc thread path")
	}
}
