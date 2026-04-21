package analyze

import (
	"fmt"
	"strings"

	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
	"github.com/IMElTgp/container-runtime-analysis/internal/util"
)

/**
 * goal:
 * - to build a mount tree for each collected mnt namespace (allow parent node missing)
 * - for each mnt tree:
 *   - check if there are mounting points with `shared` status
 *     - no `shared:xxx`, `master:xxx`, and `propagate_from:xxx` in optional fields (in mountinfo)
 *   - check if there are mount points that:
 *     - the parent node is read-only, but
 *     - the child node (if sensitive) is of read-write status
 * - check if there are vital paths (and their children) that are writable
 *   - /proc/sys(*), /sys(*), /sys/fs/cgroup(*), /dev (exception: tmpfs), /etc, /run or /var/run (also except tmpfs), /host, /rootfs, ...
 */

// mountinfo documents mount points visible from the inspected process's root.
// ordinary paths are resolved by longest-prefix matching against mount points.
// for vital path writable judgment, use trie (because of longest prefix matching)
// for example, to judge /sys/fs/cgroup,
// if in mountinfo lies:
//   /					rw
//	 /sys				ro
// 	 /sys/fs/cgroup		rw
// then /sys/fs/cgroup is rw. but, if there are no records of /sys/fs/cgroup, i.e.
// 	 /					rw
// 	 /sys				ro
// according to the longest prefix matching, /sys/fs/cgroup should be ro.
// NOTICE: /sys/fs != /sys/fs1, so the node of trie should carry the whole directory name but not
// simply partial string.

// trie is for longest prefix matching in writable path judgment
type trie struct {
	DirName     string
	Children    map[string]*trie
	MountInfos  []*collect.MountInfo // nil for internal nodes that are not mount points
	BelongingNS *model.NamespaceSnapshot
}

// mntNode represents the mounting tree node
type mntNode struct {
	Entry    *collect.MountInfo
	Children []*mntNode
}

// buildMntTree returns a mount tree built from mountinfo, in which we have parent mount ID -> child mount ID mappings
// returning a slice of mnt trees, mainly because of potential orphan nodes
func buildMntTree(mntns *model.NamespaceSnapshot) (nodes []*mntNode) {
	type pair struct {
		ID int
		mi *collect.MountInfo
	}
	// 1. build reverse maps from parentID to childID
	parent2child := make(map[int][]pair)
	// seenID checks whether an ID really exists
	seenID := make(map[int]struct{})
	for i := range mntns.MountInfo {
		info := &mntns.MountInfo[i]
		// info.MountID really exists
		seenID[info.MountID] = struct{}{}
		parent2child[info.ParentID] = append(parent2child[info.ParentID], pair{info.MountID, info})
	}
	// 2. find all roots
	// - all roots should cover one of the following conditions:
	//   - parentID = mountID (selfID), or
	//   - missing parentID=
	roots := make([]pair, 0)
	for i := range mntns.MountInfo {
		info := &mntns.MountInfo[i]
		if info.ParentID == info.MountID {
			roots = append(roots, pair{info.MountID, info})
			continue
		} else if _, ok := seenID[info.ParentID]; !ok {
			// else, check if the parentID is missing
			roots = append(roots, pair{info.MountID, info})
		}
	}
	// 3. build one mnt tree from each root
	var recursiveBuild func(pair) *mntNode
	recursiveBuild = func(r pair) *mntNode {
		node := &mntNode{Entry: r.mi, Children: make([]*mntNode, 0)}
		for i := range parent2child[r.ID] {
			child := parent2child[r.ID][i]
			if child.ID == r.ID {
				// avoid self edge
				continue
			}
			node.Children = append(node.Children, recursiveBuild(child))
		}
		return node
	}

	for _, r := range roots {
		nodes = append(nodes, recursiveBuild(r))
	}

	return
}

// buildTrie builds one trie according to all the mount points documented in MountInfo
func buildTrie(mntns *model.NamespaceSnapshot) *trie {
	if mntns == nil {
		return nil
	}

	mountPoints := make(map[string][]*collect.MountInfo)
	// 1. scan all mountinfos and record all mount points (strings)
	// 2. for those mount points (strings), record their mount entries ([]*MountInfo)
	for i := range mntns.MountInfo {
		info := &mntns.MountInfo[i]
		mountPoints[info.MountPoint] = append(mountPoints[info.MountPoint], info)
	}

	// 3. split all mount points into different levels of paths (e.g. /proc/sys -> / + /proc + /proc/sys)
	trieNodes := make(map[string]*trie)
	for path, _ := range mountPoints {
		for _, level := range util.SplitPathLevels(path) {
			if _, ok := trieNodes[level]; ok {
				continue // to avoid repeating creating trie node
			}
			trieNodes[level] = &trie{level, make(map[string]*trie), mountPoints[level], mntns}
		}
	}
	// 4. build a trie out of those paths (in which non-mount-point paths own nil MountInfos)
	for path := range trieNodes {
		if path == "/" {
			continue
		}
		parent := util.BackToLastLevel(path)
		trieNodes[parent].Children[path] = trieNodes[path]
		// no need for recursion; previous util.SplitPathLevels call promises
		// full path link covery
	}

	return trieNodes["/"]
}

// searchLongestCommonPrefixMatch returns the trie node that has the longest common
// prefix with given path **whose MountInfos section is NOT NIL**
func (t *trie) searchLongestCommonPrefixMatch(path string) (match *trie) {
	if t == nil {
		return nil
	}
	// for paths that don't have any exactly matching node in trie, return the
	// longest prefix matching node (whose MountInfos isn't nil)
	// make sure the returned trie node has a non-nil MountInfos, because to
	// judge whether a path is writable, we need to track the **mount point**
	// that has the longest common prefix with that path
	var cur = t
	// assert t is the root
	if cur.DirName != "/" {
		return nil
	}
	for _, level := range util.SplitPathLevels(path) {
		if level != "/" {
			cur = cur.Children[level] // to avoid strings.HasPrefix, which cannot handle path prefix correctly
			// for example, /sys/fs1 and /sys/fs/cgroup don't have a common prefix "/sys/fs"
		}
		if cur == nil {
			// to avoid going too deep and leading to nil pointer panic
			// e.g. path = "/sys/fs/cgroup" while deepest level = "/sys/fs"
			// when going into "cgroup", cur = nil (line 161), visit cur.MountInfos => panic!
			break
		}
		if cur.MountInfos != nil {
			match = cur // only consider mount points
		}
	}
	return
}

// searchExactPath returns the exact trie node of given path
func (t *trie) searchExactPath(path string) (match *trie) {
	levels := util.SplitPathLevels(path)
	cur := t
	for _, level := range levels {
		if level == "/" {
			continue
		}
		cur = cur.Children[level]
		if cur == nil {
			return nil
		}
	}
	return cur
}

// recursiveAnalyzeWritablePaths is the working function of judgeVitalPathWritable
func (t *trie) recursiveAnalyzeWritablePaths(root *trie, inhRisk int, vitalPath string, recursive bool) (signals []*model.Signal) {
	if root.DirName == vitalPath && root.MountInfos != nil && recursive {
		// to avoid repeating the same signal of vitalPath itself
		for _, child := range root.Children {
			signals = append(signals, t.recursiveAnalyzeWritablePaths(child, inhRisk, vitalPath, recursive)...)
		}
		return
	}
	// recursively traverse all child mount points of current vital path
	var (
		riskToInh int // risk that is going to be passed down
		// inhRisk is the risk that has been passed down to current level
	)
	switch root.DirName {
	case "/proc/sys", "/sys", "/sys/fs", "/host", "/rootfs":
		riskToInh = HighRisk
	case "/etc", "/dev", "/run", "/var/run":
		riskToInh = MediumRisk
	default:
		riskToInh = inhRisk // inherit ancestor's risk level
	}
	// search for mount points that have rw in both mount options and super options
	if root.MountInfos == nil {
		if recursive {
			for _, child := range root.Children {
				signals = append(signals, t.recursiveAnalyzeWritablePaths(child, max(riskToInh, inhRisk), vitalPath, recursive)...)
			}
		}
		return
	}

	for _, info := range root.MountInfos {
		exactPath := root.DirName
		if !recursive {
			exactPath = vitalPath
		}
		// check if MountOptions and SuperOptions contain "rw"
		if !util.ContainsString(info.MountOptions, "rw") || !util.ContainsString(info.SuperOptions, "rw") {
			continue
		}
		// both MountOptions and SuperOptions contain "rw", check fs
		if strings.HasPrefix(info.FStype, "tmpfs") {
			switch exactPath {
			case "/dev", "/run", "/var/run":
				continue
			default:
			}
		}

		// set risk level
		var (
			risk int
			inh  bool
		)
		switch exactPath {
		case "/proc/sys", "/sys", "/sys/fs", "/host", "/rootfs":
			risk = HighRisk
		case "/etc", "/dev", "/run", "/var/run":
			risk = MediumRisk
		default:
			risk = inhRisk // inherit ancestor's risk level
			inh = true
		}

		belongingNS := &target.NSRef{Type: "mnt", Dev: t.BelongingNS.Dev, Ino: t.BelongingNS.Ino}
		signalText := switchMountHandler(inh, exactPath, vitalPath)
		if signalText == nil {
			continue
		}

		signal := &model.Signal{
			Finding: model.Finding{
				Category:        "mount",
				RiskLevel:       risk,
				Evidence:        addMountEvidence(info, vitalPath, exactPath, vitalPath, inh),
				Title:           signalText[0],
				Summary:         signalText[1],
				Recommendation:  signalText[2],
				RelativeNS:      belongingNS,
				RelativeThreads: collect.ThreadsForNS(*belongingNS),
			},
		}
		riskToInh = max(risk, riskToInh)
		signals = append(signals, signal)

	}
	if recursive {
		for _, child := range root.Children {
			signals = append(signals, t.recursiveAnalyzeWritablePaths(child, max(riskToInh, inhRisk), vitalPath, recursive)...)
		}
	}
	return
}

// judgeVitalPathWritable judges whether some vital paths are writable
// in which t is the root of the trie
func (t *trie) judgeVitalPathWritable(vitalPaths []string) (signals []*model.Signal) {
	if t == nil || t.DirName != "/" {
		return nil
	}
	// traverse all vital paths and handle them separately
	for _, vitalPath := range vitalPaths {
		// pre-handle vitalPath's mount point
		preHandleMountPoint := t.searchLongestCommonPrefixMatch(vitalPath)
		if preHandleMountPoint != nil {
			signals = append(signals, t.recursiveAnalyzeWritablePaths(preHandleMountPoint, Safe, vitalPath, false)...)
		}

		match := t.searchExactPath(vitalPath)
		if match == nil {
			continue
		}
		signals = append(signals, t.recursiveAnalyzeWritablePaths(match, Safe, vitalPath, true)...)
	}
	return
}

func addMountEvidence(info *collect.MountInfo, vitalPath, signalPath, inheritedFrom string, inh bool) []string {
	if !inh {
		inheritedFrom = ""
	}
	return []string{
		fmt.Sprintf("vital_path=%s", vitalPath),
		fmt.Sprintf("signal_path=%s", signalPath),
		fmt.Sprintf("matched_mount_point=%s", info.MountPoint),
		fmt.Sprintf("inherited_from=%s", inheritedFrom),
		fmt.Sprintf("mount_id=%d", info.MountID),
		fmt.Sprintf("parent_id=%d", info.ParentID),
		fmt.Sprintf("fstype=%s", info.FStype),
		fmt.Sprintf("source=%s", info.MountSource),
		fmt.Sprintf("mount_options=%s", info.MountOptions),
		fmt.Sprintf("super_options=%s", info.SuperOptions),
	}
}

func switchMountHandler(inh bool, exactPath string, inheritedFrom string) []string {
	// return []{Title, Summary, Recommendation}
	switch exactPath {
	case "/proc/sys", "/sys", "/sys/fs":
		return handleKernelCtrlWritable(exactPath)
	case "/host", "/rootfs":
		return handleHostFSViewWritable(exactPath)
	case "/etc", "/dev", "/run", "/var/run":
		return handleSensitiveRuntimePathWritable(exactPath)
	default:
		if inh {
			return handleWritableChildMount(exactPath, inheritedFrom)
		}
	}
	return nil
}

func handleKernelCtrlWritable(exactPath string) []string {
	return []string{
		// Title
		fmt.Sprintf("Kernel control path %s is writable", exactPath),
		// Summary
		"Writable kernel control path may expose kernel tunables / control interfaces.",
		// Recommendation
		"Set this mount point to read-only; remove writable bind mount.",
	}
}

func handleHostFSViewWritable(exactPath string) []string {
	return []string{
		// Title
		fmt.Sprintf("Host filesystem view %s is writable", exactPath),
		// Summary
		"Write operations to this mount point may turn write operations inside container into editions to host filesystem.",
		// Recommendation
		"Set this mount point to read-only; narrow this mount.",
	}
}

func handleSensitiveRuntimePathWritable(exactPath string) []string {
	return []string{
		// Title
		fmt.Sprintf("Sensitive runtime path %s is writable", exactPath),
		// Summary
		"This mount option may affect settings, devices, sockets, and runtime state.",
		// Recommendation
		"Set this mount point to read-only if necessary; only assign write capability to child directories that really need.",
	}
}

func handleWritableChildMount(exactPath string, inheritedFrom string) []string {
	return []string{
		// Title
		fmt.Sprintf("Writable child mount %s inherits risk from %s", exactPath, inheritedFrom),
		// Summary
		"The child mount point opened write entry while the parent mount point seems to be under well control.",
		// Recommendation
		"Set this child mount point to read-only or move this mount point out of sensitive parent read-only path.",
	}
}

// checkRWchildUnderROParent checks if there are writable children under read-only parent in mnt tree
func (m *mntNode) checkRWchildUnderROParent() []*model.Signal {
	//TODO
	return nil
}

// checkPrivateStatus checks if there are nodes in mnt tree with non-private or unbindable status
// according to shared:xxx, master:xxx, ... in mountinfo
func (m *mntNode) checkPrivateStatus() []*model.Signal {
	// TODO
	return nil
}

func (r *Rule) AnalyzeMount() {
	// TODO
}
