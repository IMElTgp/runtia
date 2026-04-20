package analyze

import (
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/util"
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

func requireTriePath(t *testing.T, root *trie, path string) *trie {
	t.Helper()

	if root == nil {
		t.Fatalf("expected non-nil trie root")
	}
	if path == "/" {
		return root
	}

	node := root
	levels := util.SplitPathLevels(path)
	for _, level := range levels[1:] {
		next := node.Children[level]
		if next == nil {
			t.Fatalf("expected trie path %q to contain level %q", path, level)
		}
		node = next
	}
	return node
}

func requireMountIDs(t *testing.T, node *trie, mountIDs ...int) {
	t.Helper()

	if node == nil {
		t.Fatalf("expected non-nil trie node")
	}
	if len(node.MountInfos) != len(mountIDs) {
		t.Fatalf("expected mount IDs %v, got %d mount infos", mountIDs, len(node.MountInfos))
	}
	for i, mountID := range mountIDs {
		if node.MountInfos[i] == nil {
			t.Fatalf("expected mount info %d to be mount ID %d, got nil", i, mountID)
		}
		if node.MountInfos[i].MountID != mountID {
			t.Fatalf("expected mount info %d to be mount ID %d, got %d", i, mountID, node.MountInfos[i].MountID)
		}
	}
}

func requireInternalTrieNode(t *testing.T, node *trie) {
	t.Helper()

	if node == nil {
		t.Fatalf("expected non-nil trie node")
	}
	if node.MountInfos != nil {
		t.Fatalf("expected internal trie node %q to have nil mount infos, got %d", node.DirName, len(node.MountInfos))
	}
}

func requireSearchMatch(t *testing.T, root *trie, path string, mountIDs ...int) {
	t.Helper()

	match := root.searchLongestCommonPrefixMatch(path)
	requireMountIDs(t, match, mountIDs...)
}

func requireNoSearchMatch(t *testing.T, root *trie, path string) {
	t.Helper()

	if match := root.searchLongestCommonPrefixMatch(path); match != nil {
		t.Fatalf("expected no search match for %q, got %q", path, match.DirName)
	}
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

func TestBuildTrieBuildsHierarchyWithInternalNodes(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		MountInfo: []collect.MountInfo{
			{MountID: 1, MountPoint: "/"},
			{MountID: 2, MountPoint: "/sys/fs/cgroup"},
			{MountID: 3, MountPoint: "/dev/sda1"},
		},
	}

	root := buildTrie(ns)

	requireMountIDs(t, root, 1)
	requireInternalTrieNode(t, requireTriePath(t, root, "/sys"))
	requireInternalTrieNode(t, requireTriePath(t, root, "/sys/fs"))
	requireMountIDs(t, requireTriePath(t, root, "/sys/fs/cgroup"), 2)
	requireInternalTrieNode(t, requireTriePath(t, root, "/dev"))
	requireMountIDs(t, requireTriePath(t, root, "/dev/sda1"), 3)
}

func TestBuildTrieKeepsAdjacentPrefixPathsSeparate(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		MountInfo: []collect.MountInfo{
			{MountID: 1, MountPoint: "/"},
			{MountID: 2, MountPoint: "/sys/fs"},
			{MountID: 3, MountPoint: "/sys/fs1"},
			{MountID: 4, MountPoint: "/sys/fs/cgroup"},
		},
	}

	root := buildTrie(ns)

	sys := requireTriePath(t, root, "/sys")
	requireInternalTrieNode(t, sys)

	sysFS := requireTriePath(t, root, "/sys/fs")
	requireMountIDs(t, sysFS, 2)
	requireMountIDs(t, requireTriePath(t, root, "/sys/fs/cgroup"), 4)

	sysFS1 := requireTriePath(t, root, "/sys/fs1")
	requireMountIDs(t, sysFS1, 3)
	if sysFS1.Children["/sys/fs/cgroup"] != nil {
		t.Fatalf("expected /sys/fs/cgroup not to be a child of /sys/fs1")
	}
}

func TestBuildTrieGroupsDuplicateMountPoints(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		MountInfo: []collect.MountInfo{
			{MountID: 1, MountPoint: "/"},
			{MountID: 2, MountPoint: "/proc"},
			{MountID: 3, MountPoint: "/proc"},
		},
	}

	root := buildTrie(ns)
	proc := requireTriePath(t, root, "/proc")

	requireMountIDs(t, proc, 2, 3)
	if proc.MountInfos[0] != &ns.MountInfo[1] {
		t.Fatalf("expected first /proc mount info to point to original slice element")
	}
	if proc.MountInfos[1] != &ns.MountInfo[2] {
		t.Fatalf("expected second /proc mount info to point to original slice element")
	}
}

func TestBuildTrieCreatesSyntheticRootForDeepOnlyMountPoint(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		MountInfo: []collect.MountInfo{
			{MountID: 10, MountPoint: "/dev/sda1"},
		},
	}

	root := buildTrie(ns)

	requireInternalTrieNode(t, root)
	requireInternalTrieNode(t, requireTriePath(t, root, "/dev"))
	requireMountIDs(t, requireTriePath(t, root, "/dev/sda1"), 10)
}

func TestBuildTrieEmptySnapshotReturnsNil(t *testing.T) {
	root := buildTrie(&model.NamespaceSnapshot{})

	if root != nil {
		t.Fatalf("expected nil root for empty mount info, got %q", root.DirName)
	}
}

func TestSearchLongestCommonPrefixMatchExactAndDescendantMatches(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		MountInfo: []collect.MountInfo{
			{MountID: 1, MountPoint: "/"},
			{MountID: 2, MountPoint: "/proc"},
			{MountID: 3, MountPoint: "/proc/sys"},
		},
	}
	root := buildTrie(ns)

	requireSearchMatch(t, root, "/", 1)
	requireSearchMatch(t, root, "/proc", 2)
	requireSearchMatch(t, root, "/proc/sys", 3)
	requireSearchMatch(t, root, "/proc/sys/kernel", 3)
}

func TestSearchLongestCommonPrefixMatchSkipsInternalNodes(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		MountInfo: []collect.MountInfo{
			{MountID: 1, MountPoint: "/"},
			{MountID: 2, MountPoint: "/sys"},
			{MountID: 3, MountPoint: "/sys/fs/cgroup"},
		},
	}
	root := buildTrie(ns)

	requireInternalTrieNode(t, requireTriePath(t, root, "/sys/fs"))
	requireSearchMatch(t, root, "/sys/fs", 2)
	requireSearchMatch(t, root, "/sys/fs/cgroup/unified", 3)
}

func TestSearchLongestCommonPrefixMatchKeepsAdjacentPrefixesSeparate(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		MountInfo: []collect.MountInfo{
			{MountID: 1, MountPoint: "/"},
			{MountID: 2, MountPoint: "/sys/fs"},
			{MountID: 3, MountPoint: "/sys/fs1"},
		},
	}
	root := buildTrie(ns)

	requireSearchMatch(t, root, "/sys/fs/cgroup", 2)
	requireSearchMatch(t, root, "/sys/fs1/foo", 3)
	requireSearchMatch(t, root, "/sys/fs2/foo", 1)
}

func TestSearchLongestCommonPrefixMatchHandlesSyntheticRoot(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		MountInfo: []collect.MountInfo{
			{MountID: 10, MountPoint: "/dev/sda1"},
		},
	}
	root := buildTrie(ns)

	requireNoSearchMatch(t, root, "/")
	requireNoSearchMatch(t, root, "/dev")
	requireSearchMatch(t, root, "/dev/sda1/block", 10)
}

func TestSearchLongestCommonPrefixMatchHandlesNilAndNonRootReceivers(t *testing.T) {
	var root *trie
	requireNoSearchMatch(t, root, "/proc")

	nonRoot := &trie{
		DirName:    "/proc",
		Children:   make(map[string]*trie),
		MountInfos: []*collect.MountInfo{{MountID: 2, MountPoint: "/proc"}},
	}
	requireNoSearchMatch(t, nonRoot, "/proc")
}
