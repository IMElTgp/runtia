package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/model"
)

func TestWriteWarningsAsJSONWritesWarningsFile(t *testing.T) {
	tmp := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	warnings := []model.Warning{
		{
			Namespace:     "default",
			PodName:       "risk-pod",
			NodeName:      "worker-1",
			ContainerName: "app",
			ContainerID:   "containerd://app123",
			Stage:         "collect",
			Message:       "namespace warning",
		},
	}

	if err := WriteWarningsAsJSON(warnings); err != nil {
		t.Fatalf("WriteWarningsAsJSON() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmp, "warnings.json"))
	if err != nil {
		t.Fatalf("read warnings.json: %v", err)
	}
	var got []model.Warning
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal warnings.json: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one warning, got %#v", got)
	}
	if got[0].Namespace != "default" || got[0].PodName != "risk-pod" || got[0].NodeName != "worker-1" {
		t.Fatalf("expected pod context in warning JSON, got %#v", got[0])
	}
	if got[0].ContainerName != "app" || got[0].ContainerID != "containerd://app123" {
		t.Fatalf("expected container context in warning JSON, got %#v", got[0])
	}
	if got[0].Stage != "collect" || got[0].Message != "namespace warning" {
		t.Fatalf("expected stage/message in warning JSON, got %#v", got[0])
	}
}

func TestWriteWarningsAsJSONSkipsEmptyWarnings(t *testing.T) {
	tmp := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	if err := WriteWarningsAsJSON(nil); err != nil {
		t.Fatalf("WriteWarningsAsJSON(nil) error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmp, "warnings.json")); !os.IsNotExist(err) {
		t.Fatalf("expected warnings.json not to be created for empty warnings, stat err=%v", err)
	}
}

func TestWriteWarningsAsJSONSkipsEmptyNonNilWarnings(t *testing.T) {
	tmp := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	if err := WriteWarningsAsJSON([]model.Warning{}); err != nil {
		t.Fatalf("WriteWarningsAsJSON(empty slice) error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmp, "warnings.json")); !os.IsNotExist(err) {
		t.Fatalf("expected warnings.json not to be created for empty non-nil warnings, stat err=%v", err)
	}
}

func TestWriteWarningsAsJSONReturnsWriteError(t *testing.T) {
	tmp := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	if err := os.Mkdir("warnings.json", 0755); err != nil {
		t.Fatalf("create blocking directory: %v", err)
	}

	err = WriteWarningsAsJSON([]model.Warning{{Stage: "resolve", Message: "skipped"}})
	if err == nil {
		t.Fatal("expected write error when warnings.json is a directory")
	}
}
