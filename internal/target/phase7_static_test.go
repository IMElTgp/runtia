package target

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase7RuntimeCodeHasNoLegacyContainerRuntimeSurface(t *testing.T) {
	root := filepath.Join("..", "..")
	forbidden := []string{
		"dock" + "er",
		"/var/lib/" + "dock" + "er",
		"/etc/" + "dock" + "er",
		"daemon" + ".json",
		"host" + "config.json",
		"CheckUserNS" + "Remapping",
		"Resolve" + "CgroupPath(containerID",
		"extract" + "PID",
		"--container" + "-id",
	}

	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, term := range forbidden {
				if strings.Contains(string(content), term) {
					t.Fatalf("legacy container-runtime-specific term %q found in %s", term, path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
}

func TestPhase7ReadmeDocumentsK3sOnlyUsage(t *testing.T) {
	readmePath := filepath.Join("..", "..", "README.md")
	contentBytes, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	content := string(contentBytes)

	for _, want := range []string{
		"K3s Pod-only",
		"--namespace",
		"--pod",
		"sudo",
		"warnings.json",
		"real K3s smoke test",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("README.md should document %q", want)
		}
	}

	forbidden := []string{
		"dock" + "er",
		"Dock" + "er",
		"--container" + "-id",
		"dock" + "er run",
		"Dock" + "er Engine",
		"RUNTIA_NAMESPACE" + "_HELPER_IMAGE",
	}
	for _, term := range forbidden {
		if strings.Contains(content, term) {
			t.Fatalf("README.md still contains legacy user-facing term %q", term)
		}
	}
}
