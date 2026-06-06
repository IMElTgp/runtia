package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/IMElTgp/container-runtime-analysis/internal/app"
)

func main() {
	config := configFromArgs(os.Args[1:])
	if err := config.Run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func configFromArgs(args []string) *app.Config {
	flags := flag.NewFlagSet("runtia", flag.ExitOnError)
	flags.SetOutput(io.Discard)
	namespace := flags.String("namespace", "", "kubernetes namespace")
	podName := flags.String("pod", "", "kubernetes pod name")
	_ = flags.Parse(args)

	return &app.Config{
		Namespace:       *namespace,
		PodName:         *podName,
		PrintToTerminal: true,
		WriteJSON:       true,
	}
}
