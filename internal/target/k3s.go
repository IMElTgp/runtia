package target

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type RuntimeContainerID struct {
	Runtime string
	ID      string
	FullID  string
}

type ContainerTarget struct {
	Name        string
	ContainerID string
	Runtime     string
	RuntimeID   string
	InitPID     int
	CgroupPath  string
}

type PodTarget struct {
	Namespace  string
	Name       string
	NodeName   string
	Containers []ContainerTarget
}

const defaultK3sCRIEndpoint = "unix:///run/k3s/containerd/containerd.sock"

func ParseRuntimeContainerID(raw string) (RuntimeContainerID, error) {
	fullID := strings.TrimSpace(raw)
	if fullID == "" {
		return RuntimeContainerID{}, fmt.Errorf("empty container ID")
	}

	runtimeName, id, found := strings.Cut(fullID, "://")
	if !found {
		return RuntimeContainerID{ID: fullID, FullID: fullID}, nil
	}
	if runtimeName == "" || id == "" {
		return RuntimeContainerID{}, fmt.Errorf("malformed runtime container ID %q", fullID)
	}
	return RuntimeContainerID{
		Runtime: runtimeName,
		ID:      id,
		FullID:  fullID,
	}, nil
}

type podJSON struct {
	Metadata struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		NodeName   string `json:"nodeName"`
		Containers []struct {
			Name string `json:"name"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		ContainerStatuses []struct {
			Name        string `json:"name"`
			ContainerID string `json:"containerID"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

func ParsePodJSON(data []byte) (PodTarget, error) {
	var raw podJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return PodTarget{}, fmt.Errorf("parse pod JSON: %w", err)
	}

	statusByName := make(map[string]string, len(raw.Status.ContainerStatuses))
	for _, status := range raw.Status.ContainerStatuses {
		statusByName[status.Name] = status.ContainerID
	}

	pod := PodTarget{
		Namespace: raw.Metadata.Namespace,
		Name:      raw.Metadata.Name,
		NodeName:  raw.Spec.NodeName,
	}

	for _, specContainer := range raw.Spec.Containers {
		container := ContainerTarget{Name: specContainer.Name}
		containerID := strings.TrimSpace(statusByName[specContainer.Name])
		if containerID != "" {
			parsed, err := ParseRuntimeContainerID(containerID)
			if err != nil {
				return PodTarget{}, fmt.Errorf("parse containerID for container %q: %w", specContainer.Name, err)
			}
			container.ContainerID = parsed.FullID
			container.Runtime = parsed.Runtime
			container.RuntimeID = parsed.ID
		}
		pod.Containers = append(pod.Containers, container)
	}

	return pod, nil
}

func ResolvePod(namespace, podName string) (PodTarget, error) {
	out, err := exec.Command("k3s", "kubectl", "get", "pod", "-n", namespace, podName, "-o", "json").CombinedOutput()
	if err != nil {
		return PodTarget{}, fmt.Errorf("k3s kubectl get pod %s/%s failed: %w: %s", namespace, podName, err, strings.TrimSpace(string(out)))
	}
	return ParsePodJSON(out)
}

func ParseCRIInspectPID(data []byte) (int, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return 0, fmt.Errorf("parse CRI inspect JSON: %w", err)
	}

	for _, path := range [][]string{{"info", "pid"}, {"status", "pid"}, {"pid"}} {
		value, ok := jsonPath(raw, path...)
		if !ok {
			continue
		}
		pid, err := parsePIDValue(value)
		if err != nil {
			return 0, fmt.Errorf("parse PID at %s: %w", strings.Join(path, "."), err)
		}
		return pid, nil
	}

	return 0, fmt.Errorf("CRI inspect JSON does not contain a supported PID field")
}

func jsonPath(raw map[string]any, path ...string) (any, bool) {
	var current any = raw
	for _, segment := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func parsePIDValue(value any) (int, error) {
	var pid int64
	switch v := value.(type) {
	case json.Number:
		parsed, err := v.Int64()
		if err != nil {
			return 0, err
		}
		pid = parsed
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(v), 10, 0)
		if err != nil {
			return 0, err
		}
		pid = parsed
	default:
		return 0, fmt.Errorf("unsupported PID value type %T", value)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("PID must be positive, got %d", pid)
	}
	if int64(int(pid)) != pid {
		return 0, fmt.Errorf("PID overflows int: %d", pid)
	}
	return int(pid), nil
}

func ResolveContainerPIDByCRICTL(containerID string) (int, error) {
	out, err := exec.Command("crictl", crictlInspectArgs(containerID)...).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("crictl inspect %s failed: %w: %s", containerID, err, strings.TrimSpace(string(out)))
	}
	return ParseCRIInspectPID(out)
}

func crictlInspectArgs(containerID string) []string {
	args := make([]string, 0, 6)
	endpoint := strings.TrimSpace(os.Getenv("RUNTIA_CRI_ENDPOINT"))
	if endpoint == "" {
		endpoint = defaultK3sCRIEndpoint
	}
	args = append(args, "--runtime-endpoint", endpoint)
	args = append(args, "inspect", "-o", "json", containerID)
	return args
}

func ParseCgroupPathContent(content string) (string, error) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			return "", fmt.Errorf("malformed cgroup line %q", line)
		}
		cgroupPath := strings.TrimSpace(parts[2])
		if cgroupPath == "" {
			return "", fmt.Errorf("empty cgroup path in line %q", line)
		}
		cgroupPath = strings.TrimPrefix(cgroupPath, "/")
		if cgroupPath == "" {
			return "", fmt.Errorf("empty cgroup path in line %q", line)
		}
		return filepath.Join("/sys/fs/cgroup", cgroupPath), nil
	}
	return "", fmt.Errorf("empty cgroup content")
}

func ResolveCgroupPathByPID(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("PID must be positive, got %d", pid)
	}
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", fmt.Errorf("open cgroup file for pid %d failed: %w", pid, err)
	}
	return ParseCgroupPathContent(string(content))
}
