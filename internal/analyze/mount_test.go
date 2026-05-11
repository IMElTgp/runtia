package analyze

import (
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
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

func writableMount(mountID, parentID int, mountPoint, fsType string) collect.MountInfo {
	return collect.MountInfo{
		MountID:      mountID,
		ParentID:     parentID,
		MountPoint:   mountPoint,
		MountOptions: []string{"rw"},
		FStype:       fsType,
		MountSource:  fsType,
		SuperOptions: []string{"rw"},
	}
}

func mountWithOptions(mountID, parentID int, mountPoint, fsType string, mountOptions, superOptions []string) collect.MountInfo {
	return collect.MountInfo{
		MountID:      mountID,
		ParentID:     parentID,
		MountPoint:   mountPoint,
		MountOptions: mountOptions,
		FStype:       fsType,
		MountSource:  fsType,
		SuperOptions: superOptions,
	}
}

func readOnlyMount(mountID, parentID int, mountPoint, fsType string) collect.MountInfo {
	return collect.MountInfo{
		MountID:      mountID,
		ParentID:     parentID,
		MountPoint:   mountPoint,
		MountOptions: []string{"ro"},
		FStype:       fsType,
		MountSource:  fsType,
		SuperOptions: []string{"ro"},
	}
}

func withMntNSThreads(t *testing.T, ns target.NSRef, threads []*target.Thread) {
	t.Helper()

	oldThreads, existed := collect.MntNSThreads[ns]
	collect.MntNSThreads[ns] = threads
	t.Cleanup(func() {
		if existed {
			collect.MntNSThreads[ns] = oldThreads
			return
		}
		delete(collect.MntNSThreads, ns)
	})
}

func requireSignalCount(t *testing.T, signals []*model.Signal, want int) {
	t.Helper()

	if len(signals) != want {
		t.Fatalf("expected %d signals, got %d", want, len(signals))
	}
}

func requireRuleSignalCount(t *testing.T, signals []model.Signal, want int) {
	t.Helper()

	if len(signals) != want {
		t.Fatalf("expected %d rule signals, got %d", want, len(signals))
	}
}

func findSignalByTitle(signals []model.Signal, title string) *model.Signal {
	for i := range signals {
		if signals[i].Title == title {
			return &signals[i]
		}
	}
	return nil
}

func sameMountPoints(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func findSignalByTitleAndMountPoints(signals []model.Signal, title string, mountPoints ...string) *model.Signal {
	for i := range signals {
		if signals[i].Title == title && sameMountPoints(signals[i].MountPoint, mountPoints...) {
			return &signals[i]
		}
	}
	return nil
}

func countSignalsByTitle(signals []model.Signal, title string) int {
	count := 0
	for i := range signals {
		if signals[i].Title == title {
			count++
		}
	}
	return count
}

func countSignalsByNS(signals []model.Signal, ns target.NSRef) int {
	count := 0
	for i := range signals {
		if signals[i].RelativeNS != nil && *signals[i].RelativeNS == ns {
			count++
		}
	}
	return count
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

func TestCheckRWchildUnderROParentHandlesNilReceiver(t *testing.T) {
	var root *mntNode

	if got := root.checkRWchildUnderROParent(); got != nil {
		t.Fatalf("expected nil signals for nil receiver, got %d", len(got))
	}
}

func TestCheckRWchildUnderROParentHandlesMissingNamespace(t *testing.T) {
	root := &mntNode{
		Entry: &collect.MountInfo{
			MountID:      1,
			ParentID:     1,
			MountPoint:   "/",
			MountOptions: []string{"ro"},
			SuperOptions: []string{"ro"},
		},
	}

	if got := root.checkRWchildUnderROParent(); got != nil {
		t.Fatalf("expected nil signals for missing namespace, got %d", len(got))
	}
}

func TestCheckRWchildUnderROParentReturnsNoSignalForLeafNode(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		NSRef: target.NSRef{Type: "mnt", Dev: 60, Ino: 160},
		MountInfo: []collect.MountInfo{
			readOnlyMount(1, 1, "/", "ext4"),
		},
	}

	root := findRootByMountID(buildMntTree(ns), 1)
	signals := root.checkRWchildUnderROParent()
	requireSignalCount(t, signals, 0)
}

func TestCheckRWchildUnderROParentFindsDirectROToRWTransitions(t *testing.T) {
	nsRef := target.NSRef{Type: "mnt", Dev: 61, Ino: 161}
	ns := &model.NamespaceSnapshot{
		NSRef: nsRef,
		MountInfo: []collect.MountInfo{
			readOnlyMount(1, 1, "/", "ext4"),
			writableMount(2, 1, "/data", "ext4"),
		},
	}
	thread := &target.Thread{Tid: 61, Tgid: 61, Comm: "mount-check", MntNS: nsRef}
	withMntNSThreads(t, nsRef, []*target.Thread{thread})

	root := findRootByMountID(buildMntTree(ns), 1)
	signals := root.checkRWchildUnderROParent()
	requireSignalCount(t, signals, 1)

	signal := signals[0]
	if signal.Category != "mount" {
		t.Fatalf("expected mount category, got %q", signal.Category)
	}
	if signal.RiskLevel != Info {
		t.Fatalf("expected info risk %d, got %d", Info, signal.RiskLevel)
	}
	if signal.RelativeNS == nil || *signal.RelativeNS != nsRef {
		t.Fatalf("expected relative namespace %+v, got %+v", nsRef, signal.RelativeNS)
	}
	if len(signal.RelativeThreads) != 1 || signal.RelativeThreads[0] != thread {
		t.Fatalf("expected one relative thread %p, got %#v", thread, signal.RelativeThreads)
	}
	if len(signal.MountPoint) != 2 || signal.MountPoint[0] != "/" || signal.MountPoint[1] != "/data" {
		t.Fatalf("expected parent/child mount points [\"/\" \"/data\"], got %#v", signal.MountPoint)
	}
}

func TestCheckRWchildUnderROParentDoesNotRepeatAcrossWritableChain(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		NSRef: target.NSRef{Type: "mnt", Dev: 62, Ino: 162},
		MountInfo: []collect.MountInfo{
			readOnlyMount(1, 1, "/", "ext4"),
			writableMount(2, 1, "/data", "ext4"),
			writableMount(3, 2, "/data/cache", "ext4"),
		},
	}

	root := findRootByMountID(buildMntTree(ns), 1)
	signals := root.checkRWchildUnderROParent()
	requireSignalCount(t, signals, 1)

	if len(signals[0].MountPoint) != 2 || signals[0].MountPoint[0] != "/" || signals[0].MountPoint[1] != "/data" {
		t.Fatalf("expected only the first writable-island edge, got %#v", signals[0].MountPoint)
	}
}

func TestCheckRWchildUnderROParentFindsMultipleWritableIslands(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		NSRef: target.NSRef{Type: "mnt", Dev: 63, Ino: 163},
		MountInfo: []collect.MountInfo{
			readOnlyMount(1, 1, "/", "ext4"),
			writableMount(2, 1, "/data", "ext4"),
			readOnlyMount(3, 2, "/data/readonly", "ext4"),
			writableMount(4, 3, "/data/readonly/cache", "ext4"),
		},
	}

	root := findRootByMountID(buildMntTree(ns), 1)
	signals := root.checkRWchildUnderROParent()
	requireSignalCount(t, signals, 2)

	if len(signals[0].MountPoint) != 2 || signals[0].MountPoint[0] != "/" || signals[0].MountPoint[1] != "/data" {
		t.Fatalf("unexpected first transition %#v", signals[0].MountPoint)
	}
	if len(signals[1].MountPoint) != 2 || signals[1].MountPoint[0] != "/data/readonly" || signals[1].MountPoint[1] != "/data/readonly/cache" {
		t.Fatalf("unexpected second transition %#v", signals[1].MountPoint)
	}
}

func TestCheckRWchildUnderROParentRequiresWritableSuperOptions(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		NSRef: target.NSRef{Type: "mnt", Dev: 64, Ino: 164},
		MountInfo: []collect.MountInfo{
			readOnlyMount(1, 1, "/", "ext4"),
			mountWithOptions(2, 1, "/data", "ext4", []string{"rw"}, []string{"ro"}),
		},
	}

	root := findRootByMountID(buildMntTree(ns), 1)
	signals := root.checkRWchildUnderROParent()
	requireSignalCount(t, signals, 0)
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

func TestSearchExactPathMatchesExactNodesOnly(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		MountInfo: []collect.MountInfo{
			{MountID: 1, MountPoint: "/"},
			{MountID: 2, MountPoint: "/sys/fs/cgroup"},
		},
	}
	root := buildTrie(ns)

	requireMountIDs(t, root.searchExactPath("/"), 1)
	requireInternalTrieNode(t, root.searchExactPath("/sys"))
	requireInternalTrieNode(t, root.searchExactPath("/sys/fs"))
	requireMountIDs(t, root.searchExactPath("/sys/fs/cgroup"), 2)
	if match := root.searchExactPath("/sys/fs1"); match != nil {
		t.Fatalf("expected exact search miss for /sys/fs1, got %q", match.DirName)
	}
}

func TestJudgeVitalPathWritableHandlesNilAndNonRootReceivers(t *testing.T) {
	var root *trie
	if got := root.judgeVitalPathWritable([]string{"/sys"}); got != nil {
		t.Fatalf("expected nil signals for nil trie, got %d", len(got))
	}

	nonRoot := &trie{
		DirName:     "/sys",
		Children:    make(map[string]*trie),
		MountInfos:  []*collect.MountInfo{{MountID: 2, MountPoint: "/sys"}},
		BelongingNS: &model.NamespaceSnapshot{},
	}
	if got := nonRoot.judgeVitalPathWritable([]string{"/sys"}); got != nil {
		t.Fatalf("expected nil signals for non-root trie, got %d", len(got))
	}
}

func TestJudgeVitalPathWritableDirectExactSignals(t *testing.T) {
	cases := []struct {
		name      string
		vitalPath string
		title     string
		risk      int
	}{
		{
			name:      "kernel-control",
			vitalPath: "/proc/sys",
			title:     "Kernel control path /proc/sys is writable",
			risk:      HighRisk,
		},
		{
			name:      "host-view",
			vitalPath: "/host",
			title:     "Host filesystem view /host is writable",
			risk:      HighRisk,
		},
		{
			name:      "sensitive-runtime",
			vitalPath: "/etc",
			title:     "Sensitive runtime path /etc is writable",
			risk:      MediumRisk,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nsRef := target.NSRef{Type: "mnt", Dev: uint64(i + 1), Ino: uint64(i + 101)}
			ns := &model.NamespaceSnapshot{
				NSRef: nsRef,
				MountInfo: []collect.MountInfo{
					writableMount(1, 1, "/", "ext4"),
					writableMount(2, 1, tc.vitalPath, "ext4"),
				},
			}
			thread := &target.Thread{Tid: i + 1, Tgid: i + 1, Comm: "test-thread", MntNS: nsRef}
			withMntNSThreads(t, nsRef, []*target.Thread{thread})

			signals := buildTrie(ns).judgeVitalPathWritable([]string{tc.vitalPath})
			requireSignalCount(t, signals, 1)

			signal := signals[0]
			if signal.Category != "mount" {
				t.Fatalf("expected mount category, got %q", signal.Category)
			}
			if signal.Title != tc.title {
				t.Fatalf("expected title %q, got %q", tc.title, signal.Title)
			}
			if signal.RiskLevel != tc.risk {
				t.Fatalf("expected risk %d, got %d", tc.risk, signal.RiskLevel)
			}
			if signal.RelativeNS == nil || *signal.RelativeNS != nsRef {
				t.Fatalf("expected relative namespace %+v, got %+v", nsRef, signal.RelativeNS)
			}
			if len(signal.RelativeThreads) != 1 || signal.RelativeThreads[0] != thread {
				t.Fatalf("expected one relative thread %p, got %#v", thread, signal.RelativeThreads)
			}
		})
	}
}

func TestJudgeVitalPathWritableSkipsTmpfsExceptions(t *testing.T) {
	for i, vitalPath := range []string{"/dev", "/run", "/var/run"} {
		t.Run(vitalPath, func(t *testing.T) {
			ns := &model.NamespaceSnapshot{
				NSRef: target.NSRef{Type: "mnt", Dev: uint64(i + 20), Ino: uint64(i + 120)},
				MountInfo: []collect.MountInfo{
					writableMount(1, 1, "/", "ext4"),
					writableMount(2, 1, vitalPath, "tmpfs"),
				},
			}

			signals := buildTrie(ns).judgeVitalPathWritable([]string{vitalPath})
			requireSignalCount(t, signals, 0)
		})
	}
}

func TestJudgeVitalPathWritableFindsWritableChildMountsWithinExactVitalPath(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		NSRef: target.NSRef{Type: "mnt", Dev: 30, Ino: 130},
		MountInfo: []collect.MountInfo{
			readOnlyMount(1, 1, "/", "ext4"),
			readOnlyMount(2, 1, "/sys", "sysfs"),
			writableMount(3, 2, "/sys/fs/cgroup", "cgroup2"),
			writableMount(4, 2, "/sys/fs1", "tmpfs"),
		},
	}

	signals := buildTrie(ns).judgeVitalPathWritable([]string{"/sys/fs"})
	requireSignalCount(t, signals, 1)

	signal := signals[0]
	if signal.Title != "Writable child mount /sys/fs/cgroup inherits risk from /sys/fs" {
		t.Fatalf("unexpected title %q", signal.Title)
	}
	if signal.RiskLevel != HighRisk {
		t.Fatalf("expected inherited child risk %d, got %d", HighRisk, signal.RiskLevel)
	}
}

func TestJudgeVitalPathWritableReturnsNoSignalWhenNoMountPointMatches(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		NSRef: target.NSRef{Type: "mnt", Dev: 40, Ino: 140},
		MountInfo: []collect.MountInfo{
			writableMount(10, 10, "/dev/sda1", "ext4"),
		},
	}

	signals := buildTrie(ns).judgeVitalPathWritable([]string{"/proc/sys"})
	requireSignalCount(t, signals, 0)
}

func TestJudgeVitalPathWritableClassifiesDirectSensitivePathByExactPath(t *testing.T) {
	ns := &model.NamespaceSnapshot{
		NSRef: target.NSRef{Type: "mnt", Dev: 50, Ino: 150},
		MountInfo: []collect.MountInfo{
			writableMount(1, 1, "/", "ext4"),
		},
	}

	signals := buildTrie(ns).judgeVitalPathWritable([]string{"/sys/fs"})
	requireSignalCount(t, signals, 1)

	signal := signals[0]
	if signal.Title != "Kernel control path /sys/fs is writable" {
		t.Fatalf("unexpected title %q", signal.Title)
	}
	if signal.RiskLevel != HighRisk {
		t.Fatalf("expected direct /sys/fs risk %d, got %d", HighRisk, signal.RiskLevel)
	}
}

func TestAnalyzeMountAggregatesSignalsAcrossChecks(t *testing.T) {
	nsRef := target.NSRef{Type: "mnt", Dev: 70, Ino: 170}
	thread := &target.Thread{Tid: 70, Tgid: 70, Comm: "analyze-mount", MntNS: nsRef}
	withMntNSThreads(t, nsRef, []*target.Thread{thread})

	rule := &Rule{
		Snapshot: model.Snapshot{
			MountNamespaces: []model.NamespaceSnapshot{
				{
					NSRef: nsRef,
					MountInfo: []collect.MountInfo{
						readOnlyMount(1, 1, "/", "ext4"),
						writableMount(2, 1, "/dev", "ext4"),
						mountWithOptions(3, 1, "/shared", "ext4", []string{"ro"}, []string{"ro"}),
					},
				},
			},
		},
	}
	rule.Snapshot.MountNamespaces[0].MountInfo[2].OptionalFields = []string{"shared:42"}

	rule.AnalyzeMount()

	requireRuleSignalCount(t, rule.Signals, 3)

	devWritable := findSignalByTitle(rule.Signals, "Sensitive runtime path /dev is writable")
	if devWritable == nil {
		t.Fatalf("expected /dev writable signal in %#v", rule.Signals)
	}
	if devWritable.RiskLevel != MediumRisk {
		t.Fatalf("expected /dev writable risk %d, got %d", MediumRisk, devWritable.RiskLevel)
	}
	if len(devWritable.MountPoint) != 1 || devWritable.MountPoint[0] != "/dev" {
		t.Fatalf("expected /dev signal mount point [\"/dev\"], got %#v", devWritable.MountPoint)
	}
	if devWritable.RelativeNS == nil || *devWritable.RelativeNS != nsRef {
		t.Fatalf("expected /dev signal namespace %+v, got %+v", nsRef, devWritable.RelativeNS)
	}
	if len(devWritable.RelativeThreads) != 1 || devWritable.RelativeThreads[0] != thread {
		t.Fatalf("expected /dev signal thread %p, got %#v", thread, devWritable.RelativeThreads)
	}

	rwChild := findSignalByTitle(rule.Signals, "Writable child mount point under read-only parent mount point")
	if rwChild == nil {
		t.Fatalf("expected read-only to writable transition signal in %#v", rule.Signals)
	}
	if rwChild.RiskLevel != Info {
		t.Fatalf("expected transition risk %d, got %d", Info, rwChild.RiskLevel)
	}
	if len(rwChild.MountPoint) != 2 || rwChild.MountPoint[0] != "/" || rwChild.MountPoint[1] != "/dev" {
		t.Fatalf("expected transition mount points [\"/\" \"/dev\"], got %#v", rwChild.MountPoint)
	}

	shared := findSignalByTitle(rule.Signals, "Mount point with non-private status in mount tree")
	if shared == nil {
		t.Fatalf("expected shared mount propagation signal in %#v", rule.Signals)
	}
	if shared.RiskLevel != HighRisk {
		t.Fatalf("expected shared mount risk %d, got %d", HighRisk, shared.RiskLevel)
	}
	if len(shared.MountPoint) != 1 || shared.MountPoint[0] != "/shared" {
		t.Fatalf("expected shared signal mount point [\"/shared\"], got %#v", shared.MountPoint)
	}
}

func TestAnalyzeMountLeavesSignalsEmptyWhenNothingMatches(t *testing.T) {
	rule := &Rule{
		Snapshot: model.Snapshot{
			MountNamespaces: []model.NamespaceSnapshot{
				{
					NSRef: target.NSRef{Type: "mnt", Dev: 71, Ino: 171},
					MountInfo: []collect.MountInfo{
						readOnlyMount(1, 1, "/", "ext4"),
						readOnlyMount(2, 1, "/opt", "ext4"),
					},
				},
				{
					NSRef: target.NSRef{Type: "mnt", Dev: 72, Ino: 172},
				},
			},
		},
	}

	rule.AnalyzeMount()

	requireRuleSignalCount(t, rule.Signals, 0)
}

func TestAnalyzeMountReadOnlyRootRuntimeSnapshotOnlySignalsWritableRuntimeChildren(t *testing.T) {
	nsRef := target.NSRef{Type: "mnt", Dev: 80, Ino: 180}
	thread := &target.Thread{Tid: 80, Tgid: 80, Comm: "readonly-runtime", MntNS: nsRef}
	withMntNSThreads(t, nsRef, []*target.Thread{thread})

	rule := &Rule{
		Snapshot: model.Snapshot{
			MountNamespaces: []model.NamespaceSnapshot{
				{
					NSRef: nsRef,
					MountInfo: []collect.MountInfo{
						readOnlyMount(1, 1, "/", "overlay"),
						readOnlyMount(2, 1, "/proc/sys", "proc"),
						readOnlyMount(3, 1, "/sys", "sysfs"),
						readOnlyMount(4, 3, "/sys/fs/cgroup", "cgroup2"),
						readOnlyMount(5, 1, "/etc", "overlay"),
						writableMount(6, 1, "/dev", "tmpfs"),
						writableMount(7, 1, "/run", "tmpfs"),
						writableMount(8, 1, "/var/run", "tmpfs"),
					},
				},
			},
		},
	}

	rule.AnalyzeMount()

	requireRuleSignalCount(t, rule.Signals, 3)
	if countSignalsByTitle(rule.Signals, "Writable child mount point under read-only parent mount point") != 3 {
		t.Fatalf("expected 3 runtime transition signals, got %#v", rule.Signals)
	}
	if signal := findSignalByTitle(rule.Signals, "Sensitive runtime path /dev is writable"); signal != nil {
		t.Fatalf("expected tmpfs /dev not to trigger direct writable-path signal, got %#v", signal)
	}
	if signal := findSignalByTitle(rule.Signals, "Sensitive runtime path /run is writable"); signal != nil {
		t.Fatalf("expected tmpfs /run not to trigger direct writable-path signal, got %#v", signal)
	}
	if signal := findSignalByTitle(rule.Signals, "Sensitive runtime path /var/run is writable"); signal != nil {
		t.Fatalf("expected tmpfs /var/run not to trigger direct writable-path signal, got %#v", signal)
	}

	for _, mountPoints := range [][]string{{"/", "/dev"}, {"/", "/run"}, {"/", "/var/run"}} {
		signal := findSignalByTitleAndMountPoints(rule.Signals, "Writable child mount point under read-only parent mount point", mountPoints...)
		if signal == nil {
			t.Fatalf("expected runtime transition for mount points %#v in %#v", mountPoints, rule.Signals)
		}
		if signal.RelativeNS == nil || *signal.RelativeNS != nsRef {
			t.Fatalf("expected runtime transition namespace %+v, got %+v", nsRef, signal.RelativeNS)
		}
		if len(signal.RelativeThreads) != 1 || signal.RelativeThreads[0] != thread {
			t.Fatalf("expected runtime transition thread %p, got %#v", thread, signal.RelativeThreads)
		}
	}
}

func TestAnalyzeMountPrivilegedContainerSnapshotFindsDeviceAndHostExposure(t *testing.T) {
	nsRef := target.NSRef{Type: "mnt", Dev: 81, Ino: 181}
	thread := &target.Thread{Tid: 81, Tgid: 81, Comm: "privileged-container", MntNS: nsRef}
	withMntNSThreads(t, nsRef, []*target.Thread{thread})

	rule := &Rule{
		Snapshot: model.Snapshot{
			MountNamespaces: []model.NamespaceSnapshot{
				{
					NSRef: nsRef,
					MountInfo: []collect.MountInfo{
						readOnlyMount(1, 1, "/", "overlay"),
						readOnlyMount(2, 1, "/proc/sys", "proc"),
						readOnlyMount(3, 1, "/sys", "sysfs"),
						readOnlyMount(4, 1, "/etc", "overlay"),
						writableMount(5, 1, "/dev", "devtmpfs"),
						writableMount(6, 1, "/host", "ext4"),
					},
				},
			},
		},
	}
	rule.Snapshot.MountNamespaces[0].MountInfo[5].OptionalFields = []string{"shared:520"}

	rule.AnalyzeMount()

	requireRuleSignalCount(t, rule.Signals, 5)

	dev := findSignalByTitleAndMountPoints(rule.Signals, "Sensitive runtime path /dev is writable", "/dev")
	if dev == nil {
		t.Fatalf("expected direct /dev exposure signal in %#v", rule.Signals)
	}
	if dev.RiskLevel != MediumRisk {
		t.Fatalf("expected /dev signal risk %d, got %d", MediumRisk, dev.RiskLevel)
	}

	host := findSignalByTitleAndMountPoints(rule.Signals, "Host filesystem view /host is writable", "/host")
	if host == nil {
		t.Fatalf("expected direct /host exposure signal in %#v", rule.Signals)
	}
	if host.RiskLevel != HighRisk {
		t.Fatalf("expected /host signal risk %d, got %d", HighRisk, host.RiskLevel)
	}

	for _, mountPoints := range [][]string{{"/", "/dev"}, {"/", "/host"}} {
		signal := findSignalByTitleAndMountPoints(rule.Signals, "Writable child mount point under read-only parent mount point", mountPoints...)
		if signal == nil {
			t.Fatalf("expected read-only parent transition for %#v in %#v", mountPoints, rule.Signals)
		}
		if signal.RiskLevel != Info {
			t.Fatalf("expected transition risk %d, got %d", Info, signal.RiskLevel)
		}
	}

	shared := findSignalByTitleAndMountPoints(rule.Signals, "Mount point with non-private status in mount tree", "/host")
	if shared == nil {
		t.Fatalf("expected shared host mount signal in %#v", rule.Signals)
	}
	if shared.RiskLevel != HighRisk {
		t.Fatalf("expected shared host mount risk %d, got %d", HighRisk, shared.RiskLevel)
	}
}

func TestAnalyzeMountMixedSnapshotAggregatesOnlyRiskyNamespaceSignals(t *testing.T) {
	safeNS := target.NSRef{Type: "mnt", Dev: 82, Ino: 182}
	riskyNS := target.NSRef{Type: "mnt", Dev: 83, Ino: 183}
	safeThread := &target.Thread{Tid: 82, Tgid: 82, Comm: "locked-down", MntNS: safeNS}
	riskyThread := &target.Thread{Tid: 83, Tgid: 83, Comm: "host-rootfs", MntNS: riskyNS}
	withMntNSThreads(t, safeNS, []*target.Thread{safeThread})
	withMntNSThreads(t, riskyNS, []*target.Thread{riskyThread})

	rule := &Rule{
		Snapshot: model.Snapshot{
			MountNamespaces: []model.NamespaceSnapshot{
				{
					NSRef: safeNS,
					MountInfo: []collect.MountInfo{
						writableMount(1, 1, "/", "overlay"),
						readOnlyMount(2, 1, "/proc/sys", "proc"),
						readOnlyMount(3, 1, "/sys", "sysfs"),
						readOnlyMount(4, 3, "/sys/fs/cgroup", "cgroup2"),
						readOnlyMount(5, 1, "/etc", "overlay"),
						writableMount(6, 1, "/dev", "tmpfs"),
						writableMount(7, 1, "/run", "tmpfs"),
						writableMount(8, 1, "/var/run", "tmpfs"),
						readOnlyMount(9, 1, "/host", "bind"),
						readOnlyMount(10, 1, "/rootfs", "bind"),
					},
				},
				{
					NSRef: riskyNS,
					MountInfo: []collect.MountInfo{
						readOnlyMount(11, 11, "/", "overlay"),
						readOnlyMount(12, 11, "/proc/sys", "proc"),
						readOnlyMount(13, 11, "/sys", "sysfs"),
						readOnlyMount(14, 11, "/etc", "overlay"),
						writableMount(15, 11, "/rootfs", "ext4"),
					},
				},
			},
		},
	}

	rule.AnalyzeMount()

	requireRuleSignalCount(t, rule.Signals, 2)
	if countSignalsByNS(rule.Signals, safeNS) != 0 {
		t.Fatalf("expected safe namespace %+v to produce no signals, got %#v", safeNS, rule.Signals)
	}
	if countSignalsByNS(rule.Signals, riskyNS) != 2 {
		t.Fatalf("expected risky namespace %+v to produce 2 signals, got %#v", riskyNS, rule.Signals)
	}

	rootfs := findSignalByTitleAndMountPoints(rule.Signals, "Host filesystem view /rootfs is writable", "/rootfs")
	if rootfs == nil {
		t.Fatalf("expected /rootfs exposure signal in %#v", rule.Signals)
	}
	if rootfs.RelativeNS == nil || *rootfs.RelativeNS != riskyNS {
		t.Fatalf("expected /rootfs signal namespace %+v, got %+v", riskyNS, rootfs.RelativeNS)
	}
	if len(rootfs.RelativeThreads) != 1 || rootfs.RelativeThreads[0] != riskyThread {
		t.Fatalf("expected /rootfs signal thread %p, got %#v", riskyThread, rootfs.RelativeThreads)
	}

	transition := findSignalByTitleAndMountPoints(rule.Signals, "Writable child mount point under read-only parent mount point", "/", "/rootfs")
	if transition == nil {
		t.Fatalf("expected /rootfs transition signal in %#v", rule.Signals)
	}
	if transition.RelativeNS == nil || *transition.RelativeNS != riskyNS {
		t.Fatalf("expected /rootfs transition namespace %+v, got %+v", riskyNS, transition.RelativeNS)
	}
	if len(transition.RelativeThreads) != 1 || transition.RelativeThreads[0] != riskyThread {
		t.Fatalf("expected /rootfs transition thread %p, got %#v", riskyThread, transition.RelativeThreads)
	}
}

func TestAnalyzeMountDoesNotTreatWritableRootAsHostFilesystemExposure(t *testing.T) {
	nsRef := target.NSRef{Type: "mnt", Dev: 84, Ino: 184}
	thread := &target.Thread{Tid: 84, Tgid: 84, Comm: "host-userns-like", MntNS: nsRef}
	withMntNSThreads(t, nsRef, []*target.Thread{thread})

	rule := &Rule{
		Snapshot: model.Snapshot{
			MountNamespaces: []model.NamespaceSnapshot{
				{
					NSRef: nsRef,
					MountInfo: []collect.MountInfo{
						writableMount(1, 1, "/", "overlay"),
						readOnlyMount(2, 1, "/proc/sys", "proc"),
						readOnlyMount(3, 1, "/sys", "sysfs"),
						readOnlyMount(4, 3, "/sys/fs/cgroup", "cgroup2"),
						readOnlyMount(5, 1, "/etc", "overlay"),
						writableMount(6, 1, "/dev", "tmpfs"),
						writableMount(7, 1, "/run", "tmpfs"),
						writableMount(8, 1, "/var/run", "tmpfs"),
					},
				},
			},
		},
	}

	rule.AnalyzeMount()

	if signal := findSignalByTitle(rule.Signals, "Host filesystem view /host is writable"); signal != nil {
		t.Fatalf("expected no /host exposure signal when only / is writable, got %#v", signal)
	}
	if signal := findSignalByTitle(rule.Signals, "Host filesystem view /rootfs is writable"); signal != nil {
		t.Fatalf("expected no /rootfs exposure signal when only / is writable, got %#v", signal)
	}
	requireRuleSignalCount(t, rule.Signals, 0)
}
