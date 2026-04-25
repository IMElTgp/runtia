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
