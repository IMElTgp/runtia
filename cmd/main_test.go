package main

import "testing"

func TestConfigFromArgsUsesKubernetesPodInput(t *testing.T) {
	config := configFromArgs([]string{"--namespace", "default", "--pod", "risk-pod"})

	if config.Namespace != "default" {
		t.Fatalf("expected namespace default, got %q", config.Namespace)
	}
	if config.PodName != "risk-pod" {
		t.Fatalf("expected pod risk-pod, got %q", config.PodName)
	}
	if !config.PrintToTerminal {
		t.Fatalf("expected terminal output to be enabled by default")
	}
	if !config.WriteJSON {
		t.Fatalf("expected JSON output to be enabled by default")
	}
}
