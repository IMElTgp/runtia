/**
 * This implementation is just an MVP and is designed specifically for my OS and container runtime;
 * robustness shall be improved in further versions but not now.
 */

package collect

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

// parseNoNewPrivsFromStatus parses NoNewPrivs setting from /proc/<pid>/task/<tid>/status
func parseNoNewPrivsFromStatus(fileContent string) (noNewPrivs int) {
	noNewPrivs = -1 // in case collection failed
	for line := range strings.SplitSeq(fileContent, "\n") {
		if !bytes.Contains([]byte(line), []byte(":")) {
			continue
		}
		if !bytes.Contains([]byte(line), []byte("NoNewPrivs")) {
			continue
		}
		strs := strings.Split(line, ":")
		noNewPrivs, _ = strconv.Atoi(strings.TrimSpace(strs[1]))
	}
	return
}

// parseSeccompFromStatus parses Seccomp and Seccomp_Filters settings from /proc/<pid>/task<tid>/status
func parseSeccompFromStatus(fileContent string) (seccomp, seccompFilters int) {
	for line := range strings.SplitSeq(fileContent, "\n") {
		if !bytes.Contains([]byte(line), []byte(":")) {
			continue
		}
		if !strings.HasPrefix(line, "Seccomp") {
			continue
		}
		strs := strings.Split(line, ":")
		if strings.TrimSpace(strs[0]) == "Seccomp" {
			seccomp, _ = strconv.Atoi(strings.TrimSpace(strs[1]))
		} else {
			seccompFilters, _ = strconv.Atoi(strings.TrimSpace(strs[1]))
		}
	}
	return
}

func ClctSeccomp(threads map[int]*target.Thread) error {
	for tid, _ := range threads {
		path := filepath.Join("/proc", strconv.Itoa(threads[tid].Tgid), "task", strconv.Itoa(tid), "status")
		fileContent, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		seccomp, seccompFilters := parseSeccompFromStatus(string(fileContent))
		noNewPrivs := parseNoNewPrivsFromStatus(string(fileContent))
		threads[tid].SeccompMode = seccomp
		threads[tid].SeccompFilters = seccompFilters
		if noNewPrivs == 0 {
			threads[tid].NoNewPrivs = false
		} else if noNewPrivs == 1 {
			threads[tid].NoNewPrivs = true
		} else {
			return fmt.Errorf("internal/collect/seccomp.go: NoNewPrivs collection failed")
		}
	}
	return nil
}
