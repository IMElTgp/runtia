package main

import (
	"flag"
	"fmt"
	"os/exec"

	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

func main() {
	containerID := flag.String("container-id", "", "docker container ID")
	flag.Parse()

	fullPath := target.ResolveCgroupPath(*containerID)
	fmt.Println("Opening:", fullPath)
	profile, _ := exec.Command("ls", "-l", fullPath).CombinedOutput()
	fmt.Println(string(profile))
	// _ = display(fullPath)
}
