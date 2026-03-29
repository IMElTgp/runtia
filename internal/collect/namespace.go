package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

var (
	MntNSThreads  = make(map[target.NSRef][]*target.Thread)
	PIDNSThreads  = make(map[target.NSRef][]*target.Thread)
	UserNSThreads = make(map[target.NSRef][]*target.Thread)

	MntNSInfo = make(map[target.NSRef][]MountInfo)
)

type NameSpace struct {
	Threads  map[int]*target.Thread
	Type     string
	Dev, Ino uint64
}

func readLink(nsPath string, nsType string) string {
	link, _ := os.Readlink(filepath.Join(nsPath, nsType))
	return link
}

func identifyNamespace(thread *target.Thread) error {
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
		info, err := os.Stat(filepath.Join(path, e.Name()))
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("internal/collect/namespace.go: identifyNameSpace: stat_t type assertion failed")
		}
		dev, ino := st.Dev, st.Ino
		switch e.Name() {
		case "mnt":
			MntNSRef := target.NSRef{Dev: dev, Ino: ino, Type: "mnt", Link: readLink(path, "mnt")}
			thread.MntNS = MntNSRef
			MntNSThreads[MntNSRef] = append(MntNSThreads[MntNSRef], thread)
		case "pid":
			PIDNSRef := target.NSRef{Dev: dev, Ino: ino, Type: "pid", Link: readLink(path, "pid")}
			thread.PIDNS = PIDNSRef
			PIDNSThreads[PIDNSRef] = append(PIDNSThreads[PIDNSRef], thread)
		case "user":
			UserNSRef := target.NSRef{Dev: dev, Ino: ino, Type: "user", Link: readLink(path, "user")}
			thread.UserNS = UserNSRef
			UserNSThreads[UserNSRef] = append(UserNSThreads[UserNSRef], thread)
		}
	}
	return nil
}
