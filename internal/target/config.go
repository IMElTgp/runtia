package target

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type DaemonCfg struct {
	// to distinct userns-remap not exist with userns-remap is empty, use pointer instead
	UsernsRemap *string `json:"userns-remap"`
}

type HostCfg struct {
	UsernsMode string `json:"UsernsMode"`
}

// checkDaemonFile reads /etc/docker/daemon.json
// if there exists "userns-remap", return true
func checkDaemonFile() bool {
	// TODO
	f, err := os.OpenFile("/etc/docker/daemon.json", os.O_RDONLY, 0644)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// no such file as deamon.json
			return false
		}
		fmt.Printf("Err: checkDaemonFile: failed to open /etc/docker/daemon.json: %s\n", err.Error())
		return false
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		fmt.Printf("Err: checkDaemonFile: failed to read /etc/docker/daemon.json: %s\n", err.Error())
		return false
	}

	var cfg = DaemonCfg{}
	if err := json.Unmarshal(b, &cfg); err != nil {
		// fmt.Printf("Err: checkDaemonFile: failed to unmarshal json content: %s\n", err.Error())
		return false
	}

	if cfg.UsernsRemap != nil {
		return true
	}

	return false
}

// checkHostConfig reads /var/lib/docker/containers/<container-id>/hostconfig.json
// if there exists UsernsMode == "host", return false
func checkHostConfig(containerID string) bool {
	// TODO
	f, err := os.OpenFile(filepath.Join("/var/lib/docker/containers", containerID, "hostconfig.json"), os.O_RDONLY, 0644)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// no such host configuration file
			return true
		}
		fmt.Printf("Err: checkHostConfig: failed to open host config JSON file: %s\n", err.Error())
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		fmt.Printf("Err: checkHostConfig: failed to read /var/lib/docker/containers/%s/hostconfig.json: %s", containerID, err.Error())
		return true
	}

	var cfg = HostCfg{}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return true
	}

	if cfg.UsernsMode == "host" {
		return false
	}

	return true
}

// CheckUserNSRemapping checks the results of checkDaemonFile and checkHostConfig
// if checkHostConfig returns false, return false (for no userns remapping)
// if checkHostConfig returns true, check checkDaemonFile's returned value
func CheckUserNSRemapping(containerID string) bool {
	return checkDaemonFile() && checkHostConfig(containerID)
}
