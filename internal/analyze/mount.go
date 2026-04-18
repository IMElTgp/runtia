package analyze

import (
	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
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
// all nodes are mount points
type trie struct {
	// TODO
	DirName    string
	Children   map[string]*trie
	MountInfos []*collect.MountInfo
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
	// TODO
	return nil
}

// judge whether some vital paths are writable
func (t *trie) judgeVitalPathWritable(vitalPaths []string) []*model.Signal {
	// TODO
	return nil
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
