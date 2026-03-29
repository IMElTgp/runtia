package collect

import (
	"strconv"
	"strings"

	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

// /proc/<pid>/task/<tid>/mountinfo is the whole mounting tree from the perspective of the root thread of
// the mount namespace which the current thread belong to

/*
See http://man7.org/linux/man-pages/man5/proc.5.html

		   36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
		   (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)

		   (1) mount ID:  unique identifier of the mount (may be reused after umount)
		   (2) parent ID:  ID of parent (or of self for the top of the mount tree)
		   (3) major:minor:  value of st_dev for files on filesystem
		   (4) root:  root of the mount within the filesystem
		   (5) mount point:  mount point relative to the process's root
		   (6) mount options:  per mount options
		   (7) optional fields:  zero or more fields of the form "tag[:value]"
		   (8) separator:  marks the end of the optional fields
		   (9) filesystem type:  name of filesystem of the form "type[.subtype]"
		   (10) mount source:  filesystem specific information or "none"
		   (11) super options:  per super block options

		   In other words, we have:
		    * 6 mandatory fields	(1)..(6)
		    * 0 or more optional fields	(7)
		    * a separator field		(8)
		    * 3 mandatory fields	(9)..(11)
*/

type MountInfo struct {
	// RawLine is raw data kept for potential further utility
	RawLine string
	// MountID is the unique identifier of a mount point
	MountID int
	// ParentID is the parent mount point of current mount point
	ParentID int
	// Major:Minor, may be used to identify the source file system
	Major, Minor int
	// Root is the directory of the given source fs whose subtree will be mounted at MountPoint
	Root string
	// MountPoint refers to this mounting's mount point from the perspective of the mnt namespace that current thread belong to
	MountPoint string
	// MountOptions stores Optional settings of this mounting
	MountOptions []string
	// OptionalFields is a set of "tag:value" or "tag" tags/pairs
	OptionalFields []string
	// FStype refers to the file system type of the source filesystem, like ext4
	// it is of the form type[.subtype]
	FStype string
	// MountSource is the backing source of the mount, interpreted according to FStype
	// for disk fs, it is usually the device, like /dev/sda1
	// for network fs, it is usually sth like server:/export
	// for virtual fs, it is often a pseudo-name like proc, sysfs, tmpfs, overlay, or sometimes none
	MountSource string
	// SuperOptions stands for super block options, separated by commas
	SuperOptions []string
}

func parseOneLine(line string) (info MountInfo) {
	// separator: -
	before, after, _ := strings.Cut(line, "-")
	beforeParts := strings.Fields(strings.TrimSpace(before))
	afterParts := strings.Fields(strings.TrimSpace(after))
	info.RawLine = line
	info.MountID, _ = strconv.Atoi(beforeParts[0])
	info.ParentID, _ = strconv.Atoi(beforeParts[1])

	major, minor, _ := strings.Cut(beforeParts[2], ":")

	info.Major, _ = strconv.Atoi(major)
	info.Minor, _ = strconv.Atoi(minor)
	info.Root = beforeParts[3]
	info.MountPoint = beforeParts[4]

	info.MountOptions = strings.Split(beforeParts[5], ",")
	info.OptionalFields = strings.Fields(beforeParts[6])

	info.FStype = afterParts[0]
	info.MountSource = afterParts[1]
	info.SuperOptions = strings.Split(afterParts[2], ",")
	return
}

func parseMountInfo(fileContent string) (infos []MountInfo) {
	for line := range strings.SplitSeq(fileContent, "\n") {
		infos = append(infos, parseOneLine(line))
	}
	return
}

func ClctMountInfo(threads map[int]*target.Thread) error {
	// TODO: parse all namespaces of all threads first and then collect one mountinfo per mnt ns
	return nil
}
