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
