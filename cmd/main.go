package main

import (
	"flag"
	"fmt"
	"os/exec"

	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

/*
type Process struct {
	Pid        string
	IsMainProc bool
}







func getAllProcs(cgroupPath string) (procs []Process, err error) {
	procsPath := filepath.Join(cgroupPath, "cgroup.procs")
	f, err := os.Open(procsPath)
	if err != nil {
		// handle error
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()

	var (
		scanner  = bufio.NewScanner(f)
		mainProc = true
	)
	for scanner.Scan() {
		procs = append(procs, Process{scanner.Text(), mainProc})
		mainProc = false
	}
	if err = scanner.Err(); err != nil {
		panic(err)
	}
	return procs, nil
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
}*/

func main() {
	containerID := flag.String("container-id", "", "docker container ID")
	flag.Parse()

	fullPath := target.ResolveCgroupPath(*containerID)
	fmt.Println("Opening:", fullPath)
	profile, _ := exec.Command("ls", "-l", fullPath).CombinedOutput()
	fmt.Println(string(profile))
	// _ = display(fullPath)
}
