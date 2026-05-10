package collect

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

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
	// HostMntNS, HostPIDNS, HostUserNS are namespaces outside the container (from the host)
	HostMntNS, HostPIDNS, HostUserNS target.NSRef
)

const (
	namespaceHelperImageEnv     = "RUNTIA_NAMESPACE_HELPER_IMAGE"
	defaultNamespaceHelperImage = "alpine:latest"
)

// The following errors that unix.IoctlRetInt returns while getting owner user ns are acceptable
func isAcceptableOwnerUserNSError(err error) bool {
	return errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOTTY) ||
		errors.Is(err, unix.ENOSYS)
}

// The following errors that os.ReadDir returns while reading NS files are acceptable,
// but more bypass methods are needed to avoid permission denying error
func isAcceptableNamespaceAccessError(err error) bool {
	return errors.Is(err, fs.ErrPermission) ||
		errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EACCES)
}

func namespaceHelperImage() string {
	if image := strings.TrimSpace(os.Getenv(namespaceHelperImageEnv)); image != "" {
		return image
	}
	return defaultNamespaceHelperImage
}

func parseNamespaceHelperOutput(output string) (map[string]target.NSRef, error) {
	refs := make(map[string]target.NSRef)

	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 3 {
			return nil, fmt.Errorf("unexpected namespace helper output line %q", line)
		}

		dev, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse helper namespace dev from %q: %w", line, err)
		}
		ino, err := strconv.ParseUint(parts[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse helper namespace ino from %q: %w", line, err)
		}

		refs[parts[0]] = target.NSRef{Type: parts[0], Dev: dev, Ino: ino}
	}

	return refs, nil
}

func recordThreadNamespaceRefs(thread *target.Thread, refs map[string]target.NSRef, ownerUserNSByType map[string]target.NSRef) {
	if mntRef, ok := refs["mnt"]; ok {
		thread.MntNS = mntRef
		MntNSThreads[mntRef] = append(MntNSThreads[mntRef], thread)
		if owner, ok := ownerUserNSByType["mnt"]; ok {
			OwnerUserNSByNS[mntRef] = owner
		}
	}
	if pidRef, ok := refs["pid"]; ok {
		thread.PIDNS = pidRef
		PIDNSThreads[pidRef] = append(PIDNSThreads[pidRef], thread)
		if owner, ok := ownerUserNSByType["pid"]; ok {
			OwnerUserNSByNS[pidRef] = owner
		}
	}
	if userRef, ok := refs["user"]; ok {
		thread.UserNS = userRef
		UserNSThreads[userRef] = append(UserNSThreads[userRef], thread)
	}
}

// collectNamespaceViaDockerHelper is designed to bypass permission denied issue
func collectNamespaceViaDockerHelper(thread *target.Thread) error {
	script := fmt.Sprintf(
		"for ns in mnt pid user; do stat -Lc \"$ns %%d %%i\" /proc/%d/task/%d/ns/$ns; done",
		thread.Tgid,
		thread.Tid,
	)
	cmd := exec.Command(
		"docker", "run", "--rm", "--privileged", "--pid", "host", "--network", "none",
		"--security-opt", "label=disable",
		namespaceHelperImage(),
		"sh", "-c", script,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("collect namespace via docker helper for tid=%d tgid=%d failed: %w: %s", thread.Tid, thread.Tgid, err, strings.TrimSpace(string(output)))
	}

	refs, err := parseNamespaceHelperOutput(string(output))
	if err != nil {
		return fmt.Errorf("parse namespace helper output for tid=%d tgid=%d failed: %w", thread.Tid, thread.Tgid, err)
	}

	unknownOwner := target.NSRef{Type: "unknown"}
	recordThreadNamespaceRefs(thread, refs, map[string]target.NSRef{
		"mnt": unknownOwner,
		"pid": unknownOwner,
	})
	return nil
}

// getOwnerUserNS fetches a non-user namespace's belonging user ns and records that into OwnerUserNSByNS
func getOwnerUserNS(nsfd int, nsType string) error {
	var nsSt unix.Stat_t
	if err := unix.Fstat(nsfd, &nsSt); err != nil {
		return err
	}
	nsRef := target.NSRef{Dev: nsSt.Dev, Ino: nsSt.Ino, Type: nsType}

	// pass nsfd directly to avoid race condition: fd won't change on path deleting or redirecting; passing fd avoids path-based TOCTOU
	userfd, err := unix.IoctlRetInt(nsfd, unix.NS_GET_USERNS)
	if err != nil {
		if isAcceptableOwnerUserNSError(err) {
			OwnerUserNSByNS[nsRef] = target.NSRef{Type: "unknown"}
			return nil
		}
		return err
	}
	defer unix.Close(userfd)

	var st unix.Stat_t
	// use Fstat to avoid symlink
	// os.Stat returns link to the object, but unix.Fstat returns directly the object itself
	if err = unix.Fstat(userfd, &st); err != nil {
		return fmt.Errorf("fstat(userns fd): %w", err)
	}

	OwnerUserNSByNS[nsRef] = target.NSRef{Dev: st.Dev, Ino: st.Ino, Type: "user"}
	return nil
}

func ClctNamespace(thread *target.Thread) error {
	path := filepath.Join("/proc", strconv.Itoa(thread.Tgid), "task", strconv.Itoa(thread.Tid), "ns")
	entries, err := os.ReadDir(path)
	if err != nil {
		if isAcceptableNamespaceAccessError(err) {
			return collectNamespaceViaDockerHelper(thread)
		}
		return err
	}

	refs := make(map[string]target.NSRef)
	ownerUserNSByType := make(map[string]target.NSRef)
	for _, e := range entries {
		if e.IsDir() {
			// namespace files should not be directories
			return fmt.Errorf("internal/collect/namespace.go: ClctNamespace: ns directory should not contain directories")
		}
		nsPath := filepath.Join(path, e.Name())
		nsfd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			if isAcceptableNamespaceAccessError(err) {
				return collectNamespaceViaDockerHelper(thread)
			}
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
			refs["mnt"] = MntNSRef
			if err = getOwnerUserNS(nsfd, "mnt"); err != nil {
				return err
			}
			ownerUserNSByType["mnt"] = OwnerUserNSByNS[MntNSRef]
		case "pid":
			PIDNSRef := target.NSRef{Dev: dev, Ino: ino, Type: "pid"}
			refs["pid"] = PIDNSRef
			if err = getOwnerUserNS(nsfd, "pid"); err != nil {
				return err
			}
			ownerUserNSByType["pid"] = OwnerUserNSByNS[PIDNSRef]
		case "user":
			UserNSRef := target.NSRef{Dev: dev, Ino: ino, Type: "user"}
			refs["user"] = UserNSRef
		}
	}
	recordThreadNamespaceRefs(thread, refs, ownerUserNSByType)
	return nil
}

func ClctHostNamespace() error {
	// collect host namespace from /proc/self/ns/*
	path := "/proc/self/ns"
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			// as mentioned before, in ns directory, there should not be directories
			return fmt.Errorf("internal/collect/namespace.go: ClctHostNamespace: ns directory should not contain directories")
		}
		nsPath := filepath.Join(path, entry.Name())
		nsfd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}

		defer unix.Close(nsfd)

		var info unix.Stat_t
		if err := unix.Fstat(nsfd, &info); err != nil {
			return err
		}
		dev, ino := info.Dev, info.Ino

		switch entry.Name() {
		case "mnt":
			HostMntNS = target.NSRef{Dev: dev, Ino: ino, Type: "mnt"}
		case "pid":
			HostPIDNS = target.NSRef{Dev: dev, Ino: ino, Type: "pid"}
		case "user":
			HostUserNS = target.NSRef{Dev: dev, Ino: ino, Type: "user"}
		}
	}

	return nil
}

// ThreadsForNS returns the collected threads that belong to the given namespace
func ThreadsForNS(ns target.NSRef) []*target.Thread {
	var threads []*target.Thread

	switch ns.Type {
	case "mnt":
		threads = MntNSThreads[ns]
	case "pid":
		threads = PIDNSThreads[ns]
	case "user":
		threads = UserNSThreads[ns]
	default:
		return nil
	}
	// create a copy of `threads`
	// to avoid caller directly edit `threads`
	return append([]*target.Thread(nil), threads...)
}

// GetOwnerUserNS returns owner user namespace of given ns
func GetOwnerUserNS(ns target.NSRef) target.NSRef {
	return OwnerUserNSByNS[ns]
}
