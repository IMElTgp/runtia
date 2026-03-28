package collect

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

type Cap struct {
	CapInh uint64 // Inheritable
	CapPrm uint64 // Permitted
	CapEff uint64 // Effective
	CapBnd uint64 // Bounding
	CapAmb uint64 // Ambient
}

// transform hex string to uint64 value
func hexStrToUint64(hex string) (mask uint64) {
	for i := len(hex) - 1; i >= 0; i-- {
		// iterate all bits backwards
		if hex[i] >= 'a' {
			if hex[i] > 'f' {
				// this may not happen
				return 0
			}
			mask += uint64(hex[i]-'a') + 10
		} else {
			mask += uint64(hex[i] - '0')
		}
		mask <<= 4
	}
	return
}

// parseCapsFromStatus extracts capabilities from file (/proc/<pid>/task/<tid>/status)
func parseCapsFromStatus(fileContent string) (caps Cap) {
	for line := range strings.SplitSeq(fileContent, "\n") {
		if !bytes.Contains([]byte(line), []byte(":")) {
			// each line is a "key: value" pair
			continue
		}
		if !strings.HasPrefix(line, "Cap") {
			// we focus on Capabilities here
			continue
		}
		strs := strings.Split(line, ":")
		mask := hexStrToUint64(strings.TrimSpace(strs[1]))
		switch line[3:6] {
		case "Inh":
			caps.CapInh = mask
		case "Prm":
			caps.CapPrm = mask
		case "Eff":
			caps.CapEff = mask
		case "Bnd":
			caps.CapBnd = mask
		case "Amb":
			caps.CapAmb = mask
		default:
			// ignore
		}
	}
	return
}

// ClctCapabilities collects capabilities of all threads
func ClctCapabilities(threads map[int]*target.Thread) error {
	// read /proc/<tgid>/task/<tid>/status
	for tid, _ := range threads {
		path := filepath.Join("/proc", strconv.Itoa(threads[tid].Tgid), "task", strconv.Itoa(tid), "status")
		fileContent, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		capabilities := parseCapsFromStatus(string(fileContent))
		threads[tid].CapEff = capabilities.CapEff
		threads[tid].CapBnd = capabilities.CapBnd
		threads[tid].CapInh = capabilities.CapInh
		threads[tid].CapPrm = capabilities.CapPrm
		threads[tid].CapAmb = capabilities.CapAmb
	}
	return nil
}
