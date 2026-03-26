package target

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

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

func resolveCgroupPath(containerID string) string {
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
