package model

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

func TestContainerContextFromSnapshotIncludesNamespaceSummary(t *testing.T) {
	userNS := target.NSRef{Type: "user", Dev: 1, Ino: 100}
	pidNS := target.NSRef{Type: "pid", Dev: 1, Ino: 200}
	mntNS := target.NSRef{Type: "mnt", Dev: 1, Ino: 300}
	otherPIDNS := target.NSRef{Type: "pid", Dev: 1, Ino: 201}

	snapshot := Snapshot{
		Metadata: Metadata{
			ContainerName: "app",
			ContainerID:   "containerd://abc",
			Runtime:       "containerd",
			RuntimeID:     "abc",
			InitPID:       1234,
			CgroupPath:    "/sys/fs/cgroup/kubepods/app",
		},
		UserNamespaces:  []NamespaceSnapshot{{NSRef: userNS, Owner: userNS, OwnerKnown: true}},
		PIDNamespaces:   []NamespaceSnapshot{{NSRef: pidNS, Owner: userNS, OwnerKnown: true}, {NSRef: otherPIDNS, Owner: userNS, OwnerKnown: true}},
		MountNamespaces: []NamespaceSnapshot{{NSRef: mntNS, Owner: userNS, OwnerKnown: true}},
		Threads: map[int]ThreadSnapshot{
			1234: ThreadSnapshot(target.Thread{
				Tid:          1234,
				Tgid:         1234,
				IsMainThread: true,
				UserNS:       userNS,
				PIDNS:        pidNS,
				MntNS:        mntNS,
			}),
			1235: ThreadSnapshot(target.Thread{
				Tid:    1235,
				Tgid:   1234,
				UserNS: userNS,
				PIDNS:  otherPIDNS,
				MntNS:  mntNS,
			}),
		},
	}

	context := ContainerContextFromSnapshot(snapshot)
	data, err := json.Marshal(context)
	if err != nil {
		t.Fatalf("marshal container context: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		`"Name":"app"`,
		`"UserNamespaces"`,
		`"PIDNamespaces"`,
		`"MountNamespaces"`,
		`"MainUserNamespace"`,
		`"MainPIDNamespace"`,
		`"MainMountNamespace"`,
		`"Ino":100`,
		`"Ino":200`,
		`"Ino":201`,
		`"Ino":300`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected namespace summary JSON to contain %s, got %s", want, body)
		}
	}
}

func TestContainerContextFromSnapshotOmitsNamespaceSummaryWhenSnapshotHasNoNamespaces(t *testing.T) {
	context := ContainerContextFromSnapshot(Snapshot{
		Metadata: Metadata{ContainerName: "legacy"},
	})

	data, err := json.Marshal(context)
	if err != nil {
		t.Fatalf("marshal container context: %v", err)
	}
	body := string(data)

	if strings.Contains(body, "Namespaces") || strings.Contains(body, "MainUserNamespace") {
		t.Fatalf("expected empty namespace summary to be omitted, got %s", body)
	}
}
