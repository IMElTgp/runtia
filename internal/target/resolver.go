package target

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// NSRef is a reference to a namespace
type NSRef struct {
	Type     string // user/mnt/pid/etc...
	Dev, Ino uint64 // unique identifier of a namespace, got from os.Stat(path)
	Link     string // for example, mnt:[4026531840]
}

// Credentials are parsed from /proc/<pid>/task/<tid>/status, showing UIDs and GIDs, which indicate the
// thread's privileges
type Credentials struct {
	RUID, EUID, SUID, FSUID uint32
	RGID, EGID, SGID, FSGID uint32
}

// Thread represents a thread
// all the following security checks are per-thread
type Thread struct {
	Tid int
	// thread group ID (TGID)
	Tgid int
	// Comm shows what the thread really is from user's perspective
	Comm string
	// IsMainThread shows whether the thread is the main thread of the thread group
	IsMainThread bool
	// check these three namespaces:
	// 1. UserNS: check if the thread's belonging namespaces belong to the correct user ns
	// 2. MntNS: check if the thread's belonging mnt ns has mounting issues, processed lazily to avoid repetition
	// 3. PIDNS: check if the thread's belonging pid ns is the same with the owner process
	UserNS, MntNS, PIDNS NSRef
	// capabilities, in which we mainly focus on CapInh, CapPrm, CapEff, CapBnd, and CapAmb
	CapInh uint64 // Inheritable
	CapPrm uint64 // Permitted
	CapEff uint64 // Effective
	CapBnd uint64 // Bounding
	CapAmb uint64 // Ambient
	// seccomp, mode and filters
	SeccompMode    int
	SeccompFilters int
	// no further privileges adding
	NoNewPrivs bool
	// for user ns
	Creds Credentials
}

func printErr(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "[ERROR]:", err.Error())
}

// extractPID extracts container main process PID by calling docker inspect
func extractPID(containerID string) string {
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", containerID).Output()
	if err != nil {
		// handle error
		printErr(err)
		return ""
	}
	out = []byte(strings.TrimRight(string(out), "\n"))
	return string(out)
}

// ResolveCgroupPath resolves containerID into the container's cgroup path to extract all the processes inside
func ResolveCgroupPath(containerID string) string {
	fmt.Println("main process id:", extractPID(containerID))
	f, err := os.Open(filepath.Join("/proc", extractPID(containerID), "/cgroup"))
	if err != nil {
		// handle error
		printErr(err)
		return ""
	}
	defer func() {
		if err = f.Close(); err != nil {
			printErr(err)
		}
	}()
	var buf = bufio.NewReader(f)
	cgroupPath, err := buf.ReadString('\n')
	if err != nil {
		// handle error
		printErr(err)
	}
	cgroupPath = strings.TrimPrefix(cgroupPath, "0::/")
	// test
	fullPath := filepath.Join("/sys/fs/cgroup", cgroupPath)
	// clear '\n'
	fullPath = strings.TrimSpace(fullPath)
	return fullPath
}

// getComm reveals a thread's comm by reading /proc/<tid>/comm
func getComm(tid int) string {
	// the comm of all threads in one thread group (process) is the same
	comm, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(tid), "comm"))
	if err != nil {
		return ""
	}
	return string(comm)
}

// RetrieveAllThreads parses /path/to/cgroup/cgroup.procs and fetch {threadPath, threadID} for all threads
// under all procs in this cgroup (container)
func RetrieveAllThreads(path string) (threads map[int]*Thread, err error) {
	threads = make(map[int]*Thread)
	// path is the cgroup path
	procsPath := filepath.Join(path, "cgroup.procs")
	f, err := os.Open(procsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var scanner = bufio.NewScanner(f)
	for scanner.Scan() {
		pid, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
		if err != nil {
			return nil, err
		}
		tPath := filepath.Join("/proc", scanner.Text(), "task")
		entries, err := os.ReadDir(tPath)
		if err != nil {
			if os.IsNotExist(err) {
				// a process may exit after scanning and before parsing
				// don't treat that as fatal error
				continue
			}
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() {
				return nil, fmt.Errorf("target/resolver.go: RetrieveAllThreads: non-directory file in " + tPath)
			}
			tid, err := strconv.Atoi(e.Name())
			if err != nil {
				return nil, err
			}
			// threads = append(threads, Thread{Tid: tid, Path: filepath.Join(tPath, e.Name())})
			threads[tid] = &Thread{Tid: tid, Tgid: pid, IsMainThread: tid == pid, Comm: getComm(tid)}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return threads, nil
}
