package target

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase8SmokeScriptDocumentsRealK3sValidation(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "scripts", "k3s_smoke.sh")
	contentBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read smoke script: %v", err)
	}
	content := string(contentBytes)

	for _, want := range []string{
		"mktemp",
		"kubectl create namespace",
		"hostPID: true",
		"seccompProfile:",
		"type: Unconfined",
		"SYS_PTRACE",
		"KILL",
		"sudo",
		"--namespace",
		"--pod",
		"namespace.json",
		"seccomp.json",
		"capabilities.json",
		"composition.json",
		"cleanup",
		"RUNTIA_SMOKE_RESULT_FILE",
		"RUNTIA_CRI_ENDPOINT",
		"unix:///run/k3s/containerd/containerd.sock",
		"EUID",
		"on_error",
		"runtia.log",
		"runtia_log_tail:",
		"validated: runtia command completed",
		"require_json_category",
		"require_json_category namespace.json namespace",
		"require_json_category seccomp.json seccomp",
		"require_json_category capabilities.json capabilities",
		"require_json_category composition.json composition",
		"chmod 0755",
		"status: pass",
		"status: fail",
		"validated: warnings.json",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("smoke script should contain %q", want)
		}
	}
}

func TestPhase8MakeBuildDisablesVCSStamping(t *testing.T) {
	makefilePath := filepath.Join("..", "..", "Makefile")
	contentBytes, err := os.ReadFile(makefilePath)
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	if !strings.Contains(string(contentBytes), "-buildvcs=false") {
		t.Fatal("Makefile build target should disable VCS stamping so smoke builds work in unpacked or dirty worktrees")
	}
}

func TestPhase8ReadmeDocumentsSmokeScriptInputs(t *testing.T) {
	readmePath := filepath.Join("..", "..", "README.md")
	contentBytes, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	content := string(contentBytes)

	for _, want := range []string{
		"scripts/k3s_smoke.sh",
		"RUNTIA_SMOKE_RESULT_FILE",
		"RUNTIA_CRI_ENDPOINT",
		"unix:///run/k3s/containerd/containerd.sock",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("README.md should document %q", want)
		}
	}
}
