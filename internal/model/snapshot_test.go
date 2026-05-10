package model

import (
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

func TestCollectNSMarksUnknownOwnerAsNotKnown(t *testing.T) {
	oldMntNSThreads := collect.MntNSThreads
	oldPIDNSThreads := collect.PIDNSThreads
	oldUserNSThreads := collect.UserNSThreads
	oldOwnerUserNSByNS := collect.OwnerUserNSByNS
	oldMntNSInfo := collect.MntNSInfo

	collect.MntNSThreads = make(map[target.NSRef][]*target.Thread)
	collect.PIDNSThreads = make(map[target.NSRef][]*target.Thread)
	collect.UserNSThreads = make(map[target.NSRef][]*target.Thread)
	collect.OwnerUserNSByNS = make(map[target.NSRef]target.NSRef)
	collect.MntNSInfo = make(map[target.NSRef][]collect.MountInfo)

	t.Cleanup(func() {
		collect.MntNSThreads = oldMntNSThreads
		collect.PIDNSThreads = oldPIDNSThreads
		collect.UserNSThreads = oldUserNSThreads
		collect.OwnerUserNSByNS = oldOwnerUserNSByNS
		collect.MntNSInfo = oldMntNSInfo
	})

	mntNS := target.NSRef{Type: "mnt", Dev: 1, Ino: 11}
	pidNS := target.NSRef{Type: "pid", Dev: 2, Ino: 22}
	userNS := target.NSRef{Type: "user", Dev: 3, Ino: 33}
	thread := &target.Thread{Tid: 1, Tgid: 1, MntNS: mntNS, PIDNS: pidNS, UserNS: userNS}

	collect.MntNSThreads[mntNS] = []*target.Thread{thread}
	collect.PIDNSThreads[pidNS] = []*target.Thread{thread}
	collect.UserNSThreads[userNS] = []*target.Thread{thread}
	collect.OwnerUserNSByNS[mntNS] = target.NSRef{Type: "unknown"}
	collect.OwnerUserNSByNS[pidNS] = userNS

	var snapshot Snapshot
	snapshot.collectNS()

	if len(snapshot.MountNamespaces) != 1 || snapshot.MountNamespaces[0].OwnerKnown {
		t.Fatalf("expected mount namespace owner to be marked unknown, got %#v", snapshot.MountNamespaces)
	}
	if len(snapshot.PIDNamespaces) != 1 || !snapshot.PIDNamespaces[0].OwnerKnown {
		t.Fatalf("expected pid namespace owner to remain known, got %#v", snapshot.PIDNamespaces)
	}
}
