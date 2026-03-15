package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	out := extractPID(containerID)

	f, err := os.Open(filepath.Join("/proc", string(out), "/cgroup"))
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

func display(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		// handle error
		return err
	}

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			// handle error
			return err
		}
		fmt.Println(info.Name())
		fmt.Println("	Mode: " + info.Mode().String())
		fmt.Println("	Last Modified: " + info.ModTime().String())
		fmt.Println("	Size: " + strconv.FormatInt(info.Size(), 10) + "B")
	}
	return nil
}

func main() {
	containerID := flag.String("container-id", "", "docker container ID")
	flag.Parse()

	fullPath := resolveCgroupPath(*containerID)
	// profile, _ := exec.Command("ls", "-l", fullPath).CombinedOutput()
	// fmt.Println(string(profile))
	_ = display(fullPath)
}
