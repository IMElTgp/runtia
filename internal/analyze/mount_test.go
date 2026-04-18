package analyze

import (
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
)

func findChildByMountID(node *mntNode, mountID int) *mntNode {
	for _, child := range node.Children {
		if child.Entry != nil && child.Entry.MountID == mountID {
			return child
		}
	}
	return nil
}

func findRootByMountID(nodes []*mntNode, mountID int) *mntNode {
	for _, node := range nodes {
		if node.Entry != nil && node.Entry.MountID == mountID {
			return node
		}
	}
	return nil
}

func TestBuildMntTreeBuildsMountIDHierarchy(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		MountInfo: []collect.MountInfo{
			{MountID: 1, ParentID: 1, MountPoint: "/"},
			{MountID: 2, ParentID: 1, MountPoint: "/proc"},
			{MountID: 3, ParentID: 1, MountPoint: "/sys"},
			{MountID: 4, ParentID: 3, MountPoint: "/sys/fs/cgroup"},
		},
	}

	roots := buildMntTree(ns)

	if len(roots) != 1 {
		t.Fatalf("expected 1 root, got %d", len(roots))
	}
	root := roots[0]
	if root.Entry != &ns.MountInfo[0] {
		t.Fatalf("expected root entry to point to original mountinfo element")
	}
	if root.Entry.MountID != 1 {
		t.Fatalf("expected root mount ID 1, got %d", root.Entry.MountID)
	}
	if len(root.Children) != 2 {
		t.Fatalf("expected root to have 2 children, got %d", len(root.Children))
	}

	proc := findChildByMountID(root, 2)
	if proc == nil {
		t.Fatalf("expected /proc child under root")
	}
	if len(proc.Children) != 0 {
		t.Fatalf("expected /proc to have no children, got %d", len(proc.Children))
	}

	sys := findChildByMountID(root, 3)
	if sys == nil {
		t.Fatalf("expected /sys child under root")
	}
	cgroup := findChildByMountID(sys, 4)
	if cgroup == nil {
		t.Fatalf("expected /sys/fs/cgroup child under /sys")
	}
	if cgroup.Entry.MountPoint != "/sys/fs/cgroup" {
		t.Fatalf("expected cgroup mount point, got %q", cgroup.Entry.MountPoint)
	}
}

func TestBuildMntTreeKeepsMissingParentAsRoot(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		MountInfo: []collect.MountInfo{
			{MountID: 1, ParentID: 1, MountPoint: "/"},
			{MountID: 20, ParentID: 999, MountPoint: "/orphan"},
			{MountID: 21, ParentID: 20, MountPoint: "/orphan/child"},
		},
	}

	roots := buildMntTree(ns)

	if len(roots) != 2 {
		t.Fatalf("expected 2 root-like trees, got %d", len(roots))
	}
	root := findRootByMountID(roots, 1)
	if root == nil {
		t.Fatalf("expected self-parent root mount ID 1")
	}
	if findChildByMountID(root, 1) != nil {
		t.Fatalf("self-parent root should not be attached as its own child")
	}

	orphan := findRootByMountID(roots, 20)
	if orphan == nil {
		t.Fatalf("expected missing-parent mount ID 20 to become root-like")
	}
	if child := findChildByMountID(orphan, 21); child == nil {
		t.Fatalf("expected orphan child mount ID 21 under mount ID 20")
	}
}
