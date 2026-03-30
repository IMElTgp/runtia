package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/IMElTgp/container-runtime-analysis/internal/target"
	"golang.org/x/sys/unix"
)

var (
	// MntNSThreads , PIDNSThreads, and UserNSThreads are maps of namespace identity handle to a set of threads
	MntNSThreads  = make(map[target.NSRef][]*target.Thread)
	PIDNSThreads  = make(map[target.NSRef][]*target.Thread)
	UserNSThreads = make(map[target.NSRef][]*target.Thread)
	// MntNSInfo is a map which keeps a mountinfo set of each mnt ns
	MntNSInfo = make(map[target.NSRef][]MountInfo)
	// OwnerUserNSByNS represents the owner user namespace of non-user namespaces
	OwnerUserNSByNS = make(map[target.NSRef]target.NSRef)
)

// getOwnerUserNS fetches a non-user namespace's belonging user ns and records that into OwnerUserNSByNS
func getOwnerUserNS(nsfd int, nsType string) error {
	// pass nsfd directly to avoid race condition: THE PATH ISN'T SURE IN CONCURRENT CONDITIONS
	// because the kernel is highly concurrent
	// if nsPath is passed as argument and os.Stat is called to parse st, changes of thread's (ns) path may cause bugs
	userfd, err := unix.IoctlRetInt(nsfd, unix.NS_GET_USERNS)
	if err != nil {
		return err
	}
	defer unix.Close(userfd)

	var st unix.Stat_t
	// use Fstat to avoid symlink
	// os.Stat returns link to the object, but unix.Fstat returns directly the object itself
	if err = unix.Fstat(userfd, &st); err != nil {
		return fmt.Errorf("fstat(userns fd): %w", err)
	}

	var nsSt unix.Stat_t
	if err = unix.Fstat(nsfd, &nsSt); err != nil {
		return err
	}

	nsRef := target.NSRef{Dev: nsSt.Dev, Ino: nsSt.Ino, Type: nsType}

	OwnerUserNSByNS[nsRef] = target.NSRef{Dev: st.Dev, Ino: st.Ino, Type: "user"}
	return nil
}

func ClctNamespace(thread *target.Thread) error {
	path := filepath.Join("/proc", strconv.Itoa(thread.Tgid), "task", strconv.Itoa(thread.Tid), "ns")
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			// namespace files should not be directories
			return fmt.Errorf("internal/collect/namespace.go: identifyNamespace: ns directory should not contain directories")
		}
		nsPath := filepath.Join(path, e.Name())
		nsfd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		// potential memory leak, but no better choices but to open file in a for loop
		defer unix.Close(nsfd)

		var info unix.Stat_t
		// as is mentioned before, call `unix.Fstat` instead of `os.Stat` since the fd will be used multiple times
		err = unix.Fstat(nsfd, &info)
		if err != nil {
			return err
		}
		dev, ino := info.Dev, info.Ino

		switch e.Name() {
		case "mnt":
			MntNSRef := target.NSRef{Dev: dev, Ino: ino, Type: "mnt"}
			thread.MntNS = MntNSRef
			MntNSThreads[MntNSRef] = append(MntNSThreads[MntNSRef], thread)
			if err = getOwnerUserNS(nsfd, "mnt"); err != nil {
				return err
			}
		case "pid":
			PIDNSRef := target.NSRef{Dev: dev, Ino: ino, Type: "pid"}
			thread.PIDNS = PIDNSRef
			PIDNSThreads[PIDNSRef] = append(PIDNSThreads[PIDNSRef], thread)
			if err = getOwnerUserNS(nsfd, "pid"); err != nil {
				return err
			}
		case "user":
			UserNSRef := target.NSRef{Dev: dev, Ino: ino, Type: "user"}
			thread.UserNS = UserNSRef
			UserNSThreads[UserNSRef] = append(UserNSThreads[UserNSRef], thread)
		}
	}
	return nil
}
