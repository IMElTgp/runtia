package util

import (
	"path/filepath"
	"strings"
)

// SplitPathLevels split one path into different levels
// e.g. SplitPathLevels("/proc/sys") == []string{"/", "/proc", "/proc/sys"}
func SplitPathLevels(path string) (levels []string) {
	path = filepath.Clean(path)
	sep := "/"
	if path == sep {
		return []string{path}
	}

	cur := ""

	if filepath.IsAbs(path) {
		levels = append(levels, sep)
		cur = sep
		path = strings.TrimPrefix(path, sep)
	}

	for _, part := range strings.Split(path, sep) {
		if part == "" {
			continue
		}
		if cur == "" {
			cur = part
		} else {
			cur = filepath.Join(cur, part)
		}
		levels = append(levels, cur)
	}
	return
}

// BackToLastLevel returns the parent directory of given path
// e.g. BackToLastLevel("/proc/sys") == "/proc"
func BackToLastLevel(path string) string {
	cur := len(path) - 1
	for cur >= 0 && path[cur] != '/' {
		cur--
	}
	if cur <= 0 {
		// no existing '/'
		return "/"
	}
	return path[:cur]
}

// ContainsString checks whether the string slice (mainly returned by SplitPathLevels) contains a certain string
// e.g. ContainsString(SplitPathLevels("/sys/fs"), "/sys") == true
func ContainsString(strs []string, target string) bool {
	for _, str := range strs {
		if str == target {
			return true
		}
	}
	return false
}

// ContainsStringPrefix returns true if there are strings in `strs` that start with `prefix` instead of
// having to equal to given string
func ContainsStringPrefix(strs []string, prefix string) bool {
	for _, str := range strs {
		if strings.HasPrefix(str, prefix) {
			return true
		}
	}
	return false
}
