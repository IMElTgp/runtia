package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/IMElTgp/container-runtime-analysis/internal/app"
)

func main() {
	containerID := flag.String("container-id", "", "docker container ID")
	flag.Parse()

	/*fullPath := target.ResolveCgroupPath(*containerID)
	fmt.Println("Opening:", fullPath)
	profile, _ := exec.Command("ls", "-l", fullPath).CombinedOutput()
	fmt.Println(string(profile))
	// _ = display(fullPath)*/
	config := &app.Config{
		ContainerID:     *containerID,
		PrintToTerminal: true,
		WriteJSON:       true,
	}
	if err := config.Run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
