package collect

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestResetStateClearsAllCollectorGlobals(t *testing.T) {
	resetNamespaceCollectorState(t)

	mntNS := target.NSRef{Type: "mnt", Dev: 11, Ino: 111}
	pidNS := target.NSRef{Type: "pid", Dev: 22, Ino: 222}
	userNS := target.NSRef{Type: "user", Dev: 33, Ino: 333}
	ownerNS := target.NSRef{Type: "user", Dev: 44, Ino: 444}
	thread := &target.Thread{Tid: 1, Tgid: 1, MntNS: mntNS, PIDNS: pidNS, UserNS: userNS}

	MntNSThreads[mntNS] = []*target.Thread{thread}
	PIDNSThreads[pidNS] = []*target.Thread{thread}
	UserNSThreads[userNS] = []*target.Thread{thread}
	MntNSInfo[mntNS] = []MountInfo{{MountPoint: "/host"}}
	OwnerUserNSByNS[mntNS] = ownerNS
	HostMntNS = target.NSRef{Type: "mnt", Dev: 55, Ino: 555}
	HostPIDNS = target.NSRef{Type: "pid", Dev: 66, Ino: 666}
	HostUserNS = target.NSRef{Type: "user", Dev: 77, Ino: 777}

	ResetState()

	if len(MntNSThreads) != 0 {
		t.Fatalf("expected MntNSThreads to be cleared, got %#v", MntNSThreads)
	}
	if len(PIDNSThreads) != 0 {
		t.Fatalf("expected PIDNSThreads to be cleared, got %#v", PIDNSThreads)
	}
	if len(UserNSThreads) != 0 {
		t.Fatalf("expected UserNSThreads to be cleared, got %#v", UserNSThreads)
	}
	if len(MntNSInfo) != 0 {
		t.Fatalf("expected MntNSInfo to be cleared, got %#v", MntNSInfo)
	}
	if len(OwnerUserNSByNS) != 0 {
		t.Fatalf("expected OwnerUserNSByNS to be cleared, got %#v", OwnerUserNSByNS)
	}
	if HostMntNS != (target.NSRef{}) || HostPIDNS != (target.NSRef{}) || HostUserNS != (target.NSRef{}) {
		t.Fatalf("expected host namespaces to reset to zero values, got mnt=%+v pid=%+v user=%+v", HostMntNS, HostPIDNS, HostUserNS)
	}
}

func TestResetStateLeavesCollectorMapsWritable(t *testing.T) {
	resetNamespaceCollectorState(t)

	ResetState()

	mntNS := target.NSRef{Type: "mnt", Dev: 11, Ino: 111}
	pidNS := target.NSRef{Type: "pid", Dev: 22, Ino: 222}
	userNS := target.NSRef{Type: "user", Dev: 33, Ino: 333}
	ownerNS := target.NSRef{Type: "user", Dev: 44, Ino: 444}
	thread := &target.Thread{Tid: 1, Tgid: 1, MntNS: mntNS, PIDNS: pidNS, UserNS: userNS}

	MntNSThreads[mntNS] = []*target.Thread{thread}
	PIDNSThreads[pidNS] = []*target.Thread{thread}
	UserNSThreads[userNS] = []*target.Thread{thread}
	MntNSInfo[mntNS] = []MountInfo{{MountPoint: "/host"}}
	OwnerUserNSByNS[mntNS] = ownerNS

	if got := ThreadsForNS(mntNS); len(got) != 1 || got[0] != thread {
		t.Fatalf("expected reset MntNSThreads map to remain writable, got %#v", got)
	}
	if got := ThreadsForNS(pidNS); len(got) != 1 || got[0] != thread {
		t.Fatalf("expected reset PIDNSThreads map to remain writable, got %#v", got)
	}
	if got := ThreadsForNS(userNS); len(got) != 1 || got[0] != thread {
		t.Fatalf("expected reset UserNSThreads map to remain writable, got %#v", got)
	}
	if got := MntNSInfo[mntNS]; len(got) != 1 || got[0].MountPoint != "/host" {
		t.Fatalf("expected reset MntNSInfo map to remain writable, got %#v", got)
	}
	if got := GetOwnerUserNS(mntNS); got != ownerNS {
		t.Fatalf("expected reset OwnerUserNSByNS map to remain writable, got %+v", got)
	}
}

func TestResetStateRemovesOldNamespaceLookupResults(t *testing.T) {
	resetNamespaceCollectorState(t)

	mntNS := target.NSRef{Type: "mnt", Dev: 11, Ino: 111}
	pidNS := target.NSRef{Type: "pid", Dev: 22, Ino: 222}
	userNS := target.NSRef{Type: "user", Dev: 33, Ino: 333}
	thread := &target.Thread{Tid: 1, Tgid: 1, MntNS: mntNS, PIDNS: pidNS, UserNS: userNS}

	MntNSThreads[mntNS] = []*target.Thread{thread}
	PIDNSThreads[pidNS] = []*target.Thread{thread}
	UserNSThreads[userNS] = []*target.Thread{thread}
	OwnerUserNSByNS[mntNS] = userNS

	ResetState()

	if got := ThreadsForNS(mntNS); len(got) != 0 {
		t.Fatalf("expected old mount namespace lookup to be cleared, got %#v", got)
	}
	if got := ThreadsForNS(pidNS); len(got) != 0 {
		t.Fatalf("expected old pid namespace lookup to be cleared, got %#v", got)
	}
	if got := ThreadsForNS(userNS); len(got) != 0 {
		t.Fatalf("expected old user namespace lookup to be cleared, got %#v", got)
	}
	if got := GetOwnerUserNS(mntNS); got != (target.NSRef{}) {
		t.Fatalf("expected old owner user namespace lookup to be cleared, got %+v", got)
	}
}

func TestResetStateDoesNotMutateExistingThreadValues(t *testing.T) {
	resetNamespaceCollectorState(t)

	mntNS := target.NSRef{Type: "mnt", Dev: 11, Ino: 111}
	thread := &target.Thread{
		Tid:   1,
		Tgid:  1,
		Comm:  "worker",
		MntNS: mntNS,
	}
	MntNSThreads[mntNS] = []*target.Thread{thread}

	ResetState()

	if thread.Tid != 1 || thread.Tgid != 1 || thread.Comm != "worker" || thread.MntNS != mntNS {
		t.Fatalf("expected ResetState not to mutate external thread value, got %#v", thread)
	}
}

func TestCollectPackageHasNoLegacyContainerRuntimeDependency(t *testing.T) {
	files := []string{
		"namespace.go",
		"capabilites.go",
		"mount.go",
		"seccomp.go",
	}
	for _, name := range files {
		t.Run(name, func(t *testing.T) {
			content, err := os.ReadFile(name)
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			legacyRuntime := "dock" + "er"
			if strings.Contains(string(content), legacyRuntime) || strings.Contains(string(content), strings.ToUpper(legacyRuntime[:1])+legacyRuntime[1:]) {
				t.Fatalf("expected %s to contain no legacy container runtime dependency", name)
			}
		})
	}
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

	unknownOwner := target.NSRef{Type: "unknown"}
	OwnerUserNSByNS[target.NSRef{Type: "mnt", Dev: 78, Ino: 778}] = unknownOwner
	if got := GetOwnerUserNS(target.NSRef{Type: "mnt", Dev: 78, Ino: 778}); got != unknownOwner {
		t.Fatalf("expected explicit unknown owner marker, got %+v", got)
	}
}

func TestIsAcceptableOwnerUserNSError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{err: unix.EPERM, want: true},
		{err: unix.EACCES, want: true},
		{err: unix.EINVAL, want: true},
		{err: unix.ENOTTY, want: true},
		{err: unix.ENOSYS, want: true},
		{err: os.ErrNotExist, want: false},
	}

	for _, tc := range cases {
		if got := isAcceptableOwnerUserNSError(tc.err); got != tc.want {
			t.Fatalf("isAcceptableOwnerUserNSError(%v) = %t, want %t", tc.err, got, tc.want)
		}
	}
}

func TestIsAcceptableNamespaceAccessError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{err: os.ErrPermission, want: true},
		{err: unix.EPERM, want: true},
		{err: unix.EACCES, want: true},
		{err: os.ErrNotExist, want: false},
	}

	for _, tc := range cases {
		if got := isAcceptableNamespaceAccessError(tc.err); got != tc.want {
			t.Fatalf("isAcceptableNamespaceAccessError(%v) = %t, want %t", tc.err, got, tc.want)
		}
	}
}

func TestRecordThreadNamespaceRefs(t *testing.T) {
	resetNamespaceCollectorState(t)

	thread := &target.Thread{Tid: 10, Tgid: 10}
	refs := map[string]target.NSRef{
		"mnt":  {Type: "mnt", Dev: 1, Ino: 11},
		"pid":  {Type: "pid", Dev: 2, Ino: 22},
		"user": {Type: "user", Dev: 3, Ino: 33},
	}
	ownerByType := map[string]target.NSRef{
		"mnt": {Type: "unknown"},
		"pid": {Type: "user", Dev: 4, Ino: 44},
	}

	recordThreadNamespaceRefs(thread, refs, ownerByType)

	if thread.MntNS != refs["mnt"] || thread.PIDNS != refs["pid"] || thread.UserNS != refs["user"] {
		t.Fatalf("expected thread namespace refs to be recorded on thread, got %+v", thread)
	}
	if got := GetOwnerUserNS(refs["mnt"]); got != ownerByType["mnt"] {
		t.Fatalf("expected mount owner marker %+v, got %+v", ownerByType["mnt"], got)
	}
	if got := GetOwnerUserNS(refs["pid"]); got != ownerByType["pid"] {
		t.Fatalf("expected pid owner %+v, got %+v", ownerByType["pid"], got)
	}
	if got := ThreadsForNS(refs["mnt"]); len(got) != 1 || got[0] != thread {
		t.Fatalf("expected thread to be registered in mount namespace, got %#v", got)
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
