package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IMElTgp/container-runtime-analysis/internal/analyze"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/report"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

type appHooksSnapshot struct {
	resolvePod             func(namespace, podName string) (target.PodTarget, error)
	sleep                  func(time.Duration)
	hostname               func() (string, error)
	resolveContainerPID    func(containerID string) (int, error)
	resolveCgroupPathByPID func(pid int) (string, error)
	resetCollectorState    func()
	doSnapshot             func(model.Metadata) (model.Snapshot, error)
	analyzeSnapshot        func(model.Snapshot) []model.Signal
	composePodFindings     func([]analyze.PodContainerAnalysis) []*model.Finding
	printSummary           func(Config)
	printFindings          func([]*model.Finding)
	writeFindings          func([]*model.Finding) error
	writeWarnings          func([]model.Warning) error
	now                    func() time.Time
}

func saveAppHooks() appHooksSnapshot {
	return appHooksSnapshot{
		resolvePod:             resolvePod,
		sleep:                  sleep,
		hostname:               hostname,
		resolveContainerPID:    resolveContainerPID,
		resolveCgroupPathByPID: resolveCgroupPathByPID,
		resetCollectorState:    resetCollectorState,
		doSnapshot:             doSnapshot,
		analyzeSnapshot:        analyzeSnapshot,
		composePodFindings:     composePodFindings,
		printSummary:           printSummary,
		printFindings:          printFindings,
		writeFindings:          writeFindings,
		writeWarnings:          writeWarnings,
		now:                    now,
	}
}

func restoreAppHooks(hooks appHooksSnapshot) {
	resolvePod = hooks.resolvePod
	sleep = hooks.sleep
	hostname = hooks.hostname
	resolveContainerPID = hooks.resolveContainerPID
	resolveCgroupPathByPID = hooks.resolveCgroupPathByPID
	resetCollectorState = hooks.resetCollectorState
	doSnapshot = hooks.doSnapshot
	analyzeSnapshot = hooks.analyzeSnapshot
	composePodFindings = hooks.composePodFindings
	printSummary = hooks.printSummary
	printFindings = hooks.printFindings
	writeFindings = hooks.writeFindings
	writeWarnings = hooks.writeWarnings
	now = hooks.now
}

func installDefaultAppTestHooks(t *testing.T) {
	t.Helper()
	oldHooks := saveAppHooks()
	t.Cleanup(func() { restoreAppHooks(oldHooks) })

	resolvePod = func(namespace, podName string) (target.PodTarget, error) {
		return target.PodTarget{
			Namespace: namespace,
			Name:      podName,
			NodeName:  "worker-1",
			Containers: []target.ContainerTarget{
				{
					Name:        "app",
					ContainerID: "containerd://app123",
					Runtime:     "containerd",
					RuntimeID:   "app123",
				},
			},
		}, nil
	}
	sleep = func(time.Duration) {}
	hostname = func() (string, error) { return "worker-1", nil }
	resolveContainerPID = func(containerID string) (int, error) { return 1234, nil }
	resolveCgroupPathByPID = func(pid int) (string, error) { return "/sys/fs/cgroup/app", nil }
	resetCollectorState = func() {}
	doSnapshot = func(metadata model.Metadata) (model.Snapshot, error) {
		return model.Snapshot{Metadata: metadata}, nil
	}
	analyzeSnapshot = func(snapshot model.Snapshot) []model.Signal {
		thread := &target.Thread{Tid: 1234, Tgid: 1234, Comm: "app", IsMainThread: true}
		return []model.Signal{
			{
				Finding: model.Finding{
					Category:        "seccomp",
					RiskLevel:       analyze.HighRisk,
					Title:           "Thread runs without seccomp filtering",
					Evidence:        []string{"SeccompMode=0"},
					RelativeThreads: []*target.Thread{thread},
				},
			},
		}
	}
	composePodFindings = analyze.ComposePodFindings
	printSummary = func(Config) {}
	printFindings = func([]*model.Finding) {}
	writeFindings = func([]*model.Finding) error { return nil }
	writeWarnings = func([]model.Warning) error { return nil }
	now = func() time.Time { return time.Unix(1700000000, 0) }
}

func TestRunRequiresNamespaceAndPodName(t *testing.T) {
	installDefaultAppTestHooks(t)

	cases := []struct {
		name   string
		config Config
		want   string
	}{
		{
			name:   "missing namespace",
			config: Config{PodName: "risk-pod"},
			want:   "namespace",
		},
		{
			name:   "missing pod",
			config: Config{Namespace: "default"},
			want:   "pod",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Run()
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("expected error to mention %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRunRetriesOnceWhenAnyBusinessContainerMissesID(t *testing.T) {
	installDefaultAppTestHooks(t)

	resolveCalls := 0
	sleepCalls := 0
	resolvePod = func(namespace, podName string) (target.PodTarget, error) {
		resolveCalls++
		pod := target.PodTarget{
			Namespace: namespace,
			Name:      podName,
			NodeName:  "worker-1",
			Containers: []target.ContainerTarget{
				{
					Name:        "app",
					ContainerID: "containerd://app123",
					Runtime:     "containerd",
					RuntimeID:   "app123",
				},
				{Name: "sidecar"},
			},
		}
		return pod, nil
	}
	sleep = func(d time.Duration) {
		sleepCalls++
		if d != time.Second {
			t.Fatalf("expected one-second retry sleep, got %s", d)
		}
	}

	config := Config{Namespace: "default", PodName: "risk-pod"}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if resolveCalls != 2 {
		t.Fatalf("expected exactly two pod resolve calls, got %d", resolveCalls)
	}
	if sleepCalls != 1 {
		t.Fatalf("expected exactly one retry sleep, got %d", sleepCalls)
	}
	if config.ScannedContainers != 1 {
		t.Fatalf("expected one scanned container, got %d", config.ScannedContainers)
	}
	if config.SkippedContainers != 1 {
		t.Fatalf("expected one skipped container, got %d", config.SkippedContainers)
	}
	if len(config.Warnings) != 1 {
		t.Fatalf("expected one warning for missing sidecar id, got %#v", config.Warnings)
	}
	if config.Warnings[0].ContainerName != "sidecar" || config.Warnings[0].Stage != "resolve" {
		t.Fatalf("unexpected warning for missing id: %#v", config.Warnings[0])
	}
}

func TestRunRetryCanRecoverMissingContainerID(t *testing.T) {
	installDefaultAppTestHooks(t)

	resolveCalls := 0
	sleepCalls := 0
	resolvePod = func(namespace, podName string) (target.PodTarget, error) {
		resolveCalls++
		containers := []target.ContainerTarget{
			{Name: "app", ContainerID: "containerd://app123", Runtime: "containerd", RuntimeID: "app123"},
			{Name: "sidecar"},
		}
		if resolveCalls == 2 {
			containers[1] = target.ContainerTarget{Name: "sidecar", ContainerID: "containerd://sidecar456", Runtime: "containerd", RuntimeID: "sidecar456"}
		}
		return target.PodTarget{
			Namespace:  namespace,
			Name:       podName,
			NodeName:   "worker-1",
			Containers: containers,
		}, nil
	}
	sleep = func(time.Duration) { sleepCalls++ }

	config := Config{Namespace: "default", PodName: "risk-pod"}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if resolveCalls != 2 {
		t.Fatalf("expected exactly two pod resolves, got %d", resolveCalls)
	}
	if sleepCalls != 1 {
		t.Fatalf("expected exactly one sleep, got %d", sleepCalls)
	}
	if config.ScannedContainers != 2 || config.SkippedContainers != 0 {
		t.Fatalf("expected both containers to scan after retry recovery, got scanned=%d skipped=%d", config.ScannedContainers, config.SkippedContainers)
	}
	if len(config.Warnings) != 0 {
		t.Fatalf("expected no warnings after retry recovery, got %#v", config.Warnings)
	}
}

func TestRunPropagatesPodResolveErrors(t *testing.T) {
	installDefaultAppTestHooks(t)

	resolvePod = func(namespace, podName string) (target.PodTarget, error) {
		return target.PodTarget{}, errors.New("api unavailable")
	}

	config := Config{Namespace: "default", PodName: "risk-pod"}
	err := config.Run()
	if err == nil {
		t.Fatal("expected first resolve error")
	}
	if !strings.Contains(err.Error(), "api unavailable") {
		t.Fatalf("expected resolve error to propagate, got %v", err)
	}
}

func TestRunPropagatesSecondPodResolveErrorAfterRetry(t *testing.T) {
	installDefaultAppTestHooks(t)

	resolveCalls := 0
	resolvePod = func(namespace, podName string) (target.PodTarget, error) {
		resolveCalls++
		if resolveCalls == 2 {
			return target.PodTarget{}, errors.New("api unavailable on retry")
		}
		return target.PodTarget{
			Namespace: namespace,
			Name:      podName,
			NodeName:  "worker-1",
			Containers: []target.ContainerTarget{
				{Name: "app"},
			},
		}, nil
	}

	config := Config{Namespace: "default", PodName: "risk-pod"}
	err := config.Run()
	if err == nil {
		t.Fatal("expected second resolve error")
	}
	if resolveCalls != 2 {
		t.Fatalf("expected exactly two resolve calls, got %d", resolveCalls)
	}
	if !strings.Contains(err.Error(), "api unavailable on retry") {
		t.Fatalf("expected retry resolve error to propagate, got %v", err)
	}
}

func TestRunRejectsPodOnDifferentNode(t *testing.T) {
	installDefaultAppTestHooks(t)

	hostname = func() (string, error) { return "worker-2", nil }

	config := Config{Namespace: "default", PodName: "risk-pod"}
	err := config.Run()
	if err == nil {
		t.Fatal("expected node mismatch error")
	}
	if !strings.Contains(err.Error(), "worker-1") || !strings.Contains(err.Error(), "worker-2") {
		t.Fatalf("expected error to mention pod and local nodes, got %v", err)
	}
}

func TestRunAllowsEmptyPodNodeName(t *testing.T) {
	installDefaultAppTestHooks(t)

	hostnameCalls := 0
	hostname = func() (string, error) {
		hostnameCalls++
		return "worker-1", nil
	}
	resolvePod = func(namespace, podName string) (target.PodTarget, error) {
		return target.PodTarget{
			Namespace: namespace,
			Name:      podName,
			NodeName:  "",
			Containers: []target.ContainerTarget{
				{Name: "app", ContainerID: "containerd://app123", Runtime: "containerd", RuntimeID: "app123"},
			},
		}, nil
	}

	config := Config{Namespace: "default", PodName: "risk-pod"}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if hostnameCalls != 0 {
		t.Fatalf("expected hostname not to be called for empty pod node, got %d", hostnameCalls)
	}
}

func TestRunPropagatesHostnameError(t *testing.T) {
	installDefaultAppTestHooks(t)

	hostname = func() (string, error) { return "", errors.New("hostname unavailable") }

	config := Config{Namespace: "default", PodName: "risk-pod"}
	err := config.Run()
	if err == nil {
		t.Fatal("expected hostname error")
	}
	if !strings.Contains(err.Error(), "hostname unavailable") {
		t.Fatalf("expected hostname error to propagate, got %v", err)
	}
}

func TestRunSkipsContainerWhenPIDResolutionFailsAndContinues(t *testing.T) {
	installDefaultAppTestHooks(t)

	resolvePod = func(namespace, podName string) (target.PodTarget, error) {
		return target.PodTarget{
			Namespace: namespace,
			Name:      podName,
			NodeName:  "worker-1",
			Containers: []target.ContainerTarget{
				{Name: "bad", ContainerID: "containerd://bad123", Runtime: "containerd", RuntimeID: "bad123"},
				{Name: "good", ContainerID: "containerd://good456", Runtime: "containerd", RuntimeID: "good456"},
			},
		}, nil
	}
	resolveContainerPID = func(containerID string) (int, error) {
		if containerID == "bad123" {
			return 0, errors.New("cri unavailable")
		}
		return 5678, nil
	}

	config := Config{Namespace: "default", PodName: "risk-pod"}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if config.ScannedContainers != 1 || config.SkippedContainers != 1 {
		t.Fatalf("expected one scanned and one skipped container, got scanned=%d skipped=%d", config.ScannedContainers, config.SkippedContainers)
	}
	if len(config.Warnings) != 1 {
		t.Fatalf("expected one warning, got %#v", config.Warnings)
	}
	if config.Warnings[0].ContainerName != "bad" || config.Warnings[0].Stage != "resolve-pid" {
		t.Fatalf("unexpected PID warning: %#v", config.Warnings[0])
	}
}

func TestRunSkipsContainerWhenCgroupResolutionFails(t *testing.T) {
	installDefaultAppTestHooks(t)

	resolveCgroupPathByPID = func(pid int) (string, error) {
		return "", errors.New("cgroup unavailable")
	}
	snapshotCalls := 0
	doSnapshot = func(metadata model.Metadata) (model.Snapshot, error) {
		snapshotCalls++
		return model.Snapshot{Metadata: metadata}, nil
	}

	config := Config{Namespace: "default", PodName: "risk-pod"}
	err := config.Run()
	if err == nil {
		t.Fatal("expected all-skipped error")
	}
	if config.ScannedContainers != 0 || config.SkippedContainers != 1 {
		t.Fatalf("expected cgroup failure to skip one container, got scanned=%d skipped=%d", config.ScannedContainers, config.SkippedContainers)
	}
	if snapshotCalls != 0 {
		t.Fatalf("expected snapshot not to run after cgroup failure, got %d calls", snapshotCalls)
	}
	if len(config.Warnings) != 1 || config.Warnings[0].Stage != "resolve-cgroup" {
		t.Fatalf("expected resolve-cgroup warning, got %#v", config.Warnings)
	}
}

func TestRunSkipsContainerWhenSnapshotFails(t *testing.T) {
	installDefaultAppTestHooks(t)

	doSnapshot = func(metadata model.Metadata) (model.Snapshot, error) {
		return model.Snapshot{}, errors.New("snapshot failed")
	}

	config := Config{Namespace: "default", PodName: "risk-pod"}
	err := config.Run()
	if err == nil {
		t.Fatal("expected all-skipped error")
	}
	if config.ScannedContainers != 0 || config.SkippedContainers != 1 {
		t.Fatalf("expected snapshot failure to skip one container, got scanned=%d skipped=%d", config.ScannedContainers, config.SkippedContainers)
	}
	if len(config.Warnings) != 1 || config.Warnings[0].Stage != "collect" || !strings.Contains(config.Warnings[0].Message, "snapshot failed") {
		t.Fatalf("expected collect warning for snapshot failure, got %#v", config.Warnings)
	}
}

func TestRunPreservesSnapshotWarningsWithoutSkippingContainer(t *testing.T) {
	installDefaultAppTestHooks(t)

	doSnapshot = func(metadata model.Metadata) (model.Snapshot, error) {
		return model.Snapshot{
			Metadata: metadata,
			Warnings: []string{
				"namespace warning",
				"mount warning",
			},
		}, nil
	}

	config := Config{Namespace: "default", PodName: "risk-pod"}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if config.ScannedContainers != 1 || config.SkippedContainers != 0 {
		t.Fatalf("expected snapshot warnings not to skip container, got scanned=%d skipped=%d", config.ScannedContainers, config.SkippedContainers)
	}
	if len(config.Warnings) != 2 {
		t.Fatalf("expected two snapshot warnings, got %#v", config.Warnings)
	}
	for _, warning := range config.Warnings {
		if warning.Stage != "collect" || warning.ContainerName != "app" || warning.PodName != "risk-pod" {
			t.Fatalf("unexpected snapshot warning context: %#v", warning)
		}
	}
}

func TestRunFailsWhenAllContainersAreSkipped(t *testing.T) {
	installDefaultAppTestHooks(t)

	resolveContainerPID = func(containerID string) (int, error) {
		return 0, errors.New("cri unavailable")
	}

	config := Config{Namespace: "default", PodName: "risk-pod"}
	err := config.Run()
	if err == nil {
		t.Fatal("expected all-skipped error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "no containers") {
		t.Fatalf("expected all-skipped error to mention no containers, got %v", err)
	}
	if config.ScannedContainers != 0 || config.SkippedContainers != 1 {
		t.Fatalf("expected zero scanned and one skipped container, got scanned=%d skipped=%d", config.ScannedContainers, config.SkippedContainers)
	}
}

func TestRunFailsWhenPodHasNoBusinessContainers(t *testing.T) {
	installDefaultAppTestHooks(t)

	resolvePod = func(namespace, podName string) (target.PodTarget, error) {
		return target.PodTarget{
			Namespace:  namespace,
			Name:       podName,
			NodeName:   "worker-1",
			Containers: nil,
		}, nil
	}

	config := Config{Namespace: "default", PodName: "risk-pod"}
	err := config.Run()
	if err == nil {
		t.Fatal("expected empty pod container list to fail")
	}
	if config.ScannedContainers != 0 || config.SkippedContainers != 0 {
		t.Fatalf("expected no scanned or skipped containers, got scanned=%d skipped=%d", config.ScannedContainers, config.SkippedContainers)
	}
}

func TestRunResetsCollectorStateBeforeEachSuccessfulContainerScan(t *testing.T) {
	installDefaultAppTestHooks(t)

	resolvePod = func(namespace, podName string) (target.PodTarget, error) {
		return target.PodTarget{
			Namespace: namespace,
			Name:      podName,
			NodeName:  "worker-1",
			Containers: []target.ContainerTarget{
				{Name: "app", ContainerID: "containerd://app123", Runtime: "containerd", RuntimeID: "app123"},
				{Name: "sidecar", ContainerID: "containerd://sidecar456", Runtime: "containerd", RuntimeID: "sidecar456"},
			},
		}, nil
	}
	resetCalls := 0
	resetCollectorState = func() { resetCalls++ }

	config := Config{Namespace: "default", PodName: "risk-pod"}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if resetCalls != 2 {
		t.Fatalf("expected reset before each successful container scan, got %d", resetCalls)
	}
	if config.ScannedContainers != 2 {
		t.Fatalf("expected two scanned containers, got %d", config.ScannedContainers)
	}
}

func TestRunDoesNotResetCollectorStateBeforePIDOrCgroupFailure(t *testing.T) {
	installDefaultAppTestHooks(t)

	resetCalls := 0
	resetCollectorState = func() { resetCalls++ }

	resolveContainerPID = func(containerID string) (int, error) {
		return 0, errors.New("pid unavailable")
	}
	config := Config{Namespace: "default", PodName: "risk-pod"}
	if err := config.Run(); err == nil {
		t.Fatal("expected PID failure to make run fail")
	}
	if resetCalls != 0 {
		t.Fatalf("expected no reset before PID failure, got %d", resetCalls)
	}

	installDefaultAppTestHooks(t)
	resetCalls = 0
	resetCollectorState = func() { resetCalls++ }
	resolveCgroupPathByPID = func(pid int) (string, error) {
		return "", errors.New("cgroup unavailable")
	}
	config = Config{Namespace: "default", PodName: "risk-pod"}
	if err := config.Run(); err == nil {
		t.Fatal("expected cgroup failure to make run fail")
	}
	if resetCalls != 0 {
		t.Fatalf("expected no reset before cgroup failure, got %d", resetCalls)
	}
}

func TestRunResetsCollectorStateBeforeSnapshotFailure(t *testing.T) {
	installDefaultAppTestHooks(t)

	resetCalls := 0
	resetCollectorState = func() { resetCalls++ }
	doSnapshot = func(metadata model.Metadata) (model.Snapshot, error) {
		return model.Snapshot{}, errors.New("snapshot failed")
	}

	config := Config{Namespace: "default", PodName: "risk-pod"}
	if err := config.Run(); err == nil {
		t.Fatal("expected snapshot failure to make run fail")
	}
	if resetCalls != 1 {
		t.Fatalf("expected reset before snapshot attempt, got %d", resetCalls)
	}
}

func TestRunPassesCompleteMetadataToSnapshot(t *testing.T) {
	installDefaultAppTestHooks(t)

	var got model.Metadata
	doSnapshot = func(metadata model.Metadata) (model.Snapshot, error) {
		got = metadata
		return model.Snapshot{Metadata: metadata}, nil
	}

	config := Config{Namespace: "default", PodName: "risk-pod"}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got.CollectedAt != time.Unix(1700000000, 0) {
		t.Fatalf("unexpected collectedAt %v", got.CollectedAt)
	}
	if got.Namespace != "default" || got.PodName != "risk-pod" || got.NodeName != "worker-1" {
		t.Fatalf("unexpected pod metadata %#v", got)
	}
	if got.ContainerName != "app" || got.ContainerID != "containerd://app123" || got.Runtime != "containerd" || got.RuntimeID != "app123" {
		t.Fatalf("unexpected container metadata %#v", got)
	}
	if got.InitPID != 1234 || got.CgroupPath != "/sys/fs/cgroup/app" {
		t.Fatalf("unexpected runtime metadata %#v", got)
	}
}

func TestRunPassesFullContainerIDWhenRuntimeIDIsMissing(t *testing.T) {
	installDefaultAppTestHooks(t)

	resolvePod = func(namespace, podName string) (target.PodTarget, error) {
		return target.PodTarget{
			Namespace: namespace,
			Name:      podName,
			NodeName:  "worker-1",
			Containers: []target.ContainerTarget{
				{Name: "app", ContainerID: "containerd://app123", Runtime: "containerd"},
			},
		}, nil
	}
	var gotID string
	resolveContainerPID = func(containerID string) (int, error) {
		gotID = containerID
		return 1234, nil
	}

	config := Config{Namespace: "default", PodName: "risk-pod"}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if gotID != "containerd://app123" {
		t.Fatalf("expected full container ID fallback when RuntimeID is missing, got %q", gotID)
	}
}

func TestRunAttachesPodAndContainerContextToFindings(t *testing.T) {
	installDefaultAppTestHooks(t)

	config := Config{Namespace: "default", PodName: "risk-pod"}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(config.Findings) != 1 {
		t.Fatalf("expected one finding, got %#v", config.Findings)
	}
	finding := config.Findings[0]
	if finding.Namespace != "default" || finding.PodName != "risk-pod" || finding.NodeName != "worker-1" {
		t.Fatalf("expected finding pod context, got %#v", finding)
	}
	if len(finding.Containers) != 1 {
		t.Fatalf("expected one container context, got %#v", finding.Containers)
	}
	if finding.Containers[0].Name != "app" || finding.Containers[0].ContainerID != "containerd://app123" || finding.Containers[0].InitPID != 1234 {
		t.Fatalf("unexpected container context %#v", finding.Containers[0])
	}
	joinedEvidence := strings.Join(finding.Evidence, "\n")
	if !strings.Contains(joinedEvidence, "pod=default/risk-pod") || !strings.Contains(joinedEvidence, "container name=app") {
		t.Fatalf("expected readable context evidence, got %#v", finding.Evidence)
	}
}

func TestRunHonorsOutputTogglesAndPropagatesWriteError(t *testing.T) {
	installDefaultAppTestHooks(t)

	summaryCalls := 0
	printCalls := 0
	writeCalls := 0
	warningWriteCalls := 0
	printSummary = func(Config) { summaryCalls++ }
	printFindings = func([]*model.Finding) { printCalls++ }
	writeFindings = func([]*model.Finding) error {
		writeCalls++
		return nil
	}
	writeWarnings = func([]model.Warning) error {
		warningWriteCalls++
		return nil
	}

	config := Config{
		Namespace:       "default",
		PodName:         "risk-pod",
		PrintToTerminal: false,
		WriteJSON:       false,
	}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if summaryCalls != 0 {
		t.Fatalf("expected summary hook not to be called, got %d", summaryCalls)
	}
	if printCalls != 0 {
		t.Fatalf("expected print hook not to be called, got %d", printCalls)
	}
	if writeCalls != 0 {
		t.Fatalf("expected write hook not to be called, got %d", writeCalls)
	}
	if warningWriteCalls != 0 {
		t.Fatalf("expected warning write hook not to be called, got %d", warningWriteCalls)
	}

	installDefaultAppTestHooks(t)
	writeFindings = func([]*model.Finding) error {
		return errors.New("write failed")
	}
	config = Config{Namespace: "default", PodName: "risk-pod", WriteJSON: true}
	err := config.Run()
	if err == nil {
		t.Fatal("expected write error")
	}
	if !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("expected write error to propagate, got %v", err)
	}
}

func TestRunPrintsSummaryAndFindingsWhenTerminalOutputEnabled(t *testing.T) {
	installDefaultAppTestHooks(t)

	var gotSummary Config
	summaryCalls := 0
	findingsCalls := 0
	printSummary = func(config Config) {
		summaryCalls++
		gotSummary = config
	}
	printFindings = func([]*model.Finding) { findingsCalls++ }

	config := Config{Namespace: "default", PodName: "risk-pod", PrintToTerminal: true}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if summaryCalls != 1 {
		t.Fatalf("expected one summary print, got %d", summaryCalls)
	}
	if findingsCalls != 1 {
		t.Fatalf("expected one findings print, got %d", findingsCalls)
	}
	if gotSummary.Namespace != "default" || gotSummary.PodName != "risk-pod" {
		t.Fatalf("expected summary config to include scan target, got %#v", gotSummary)
	}
	if gotSummary.ScannedContainers != 1 || gotSummary.SkippedContainers != 0 || len(gotSummary.Warnings) != 0 {
		t.Fatalf("unexpected summary counts: scanned=%d skipped=%d warnings=%d", gotSummary.ScannedContainers, gotSummary.SkippedContainers, len(gotSummary.Warnings))
	}
}

func TestRunSummaryIncludesNodeWhenScanHasNoFindings(t *testing.T) {
	installDefaultAppTestHooks(t)

	analyzeSnapshot = func(snapshot model.Snapshot) []model.Signal {
		return nil
	}
	var gotSummary Config
	printSummary = func(config Config) {
		gotSummary = config
	}

	config := Config{Namespace: "default", PodName: "risk-pod", PrintToTerminal: true}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if gotSummary.NodeName != "worker-1" {
		t.Fatalf("expected summary to include node even with zero findings, got %#v", gotSummary)
	}
	if len(gotSummary.Findings) != 0 {
		t.Fatalf("expected zero findings in summary, got %#v", gotSummary.Findings)
	}
	if gotSummary.ScannedContainers != 1 || gotSummary.SkippedContainers != 0 {
		t.Fatalf("unexpected summary counts: scanned=%d skipped=%d", gotSummary.ScannedContainers, gotSummary.SkippedContainers)
	}
}

func TestRunWritesEmptyWarningsSliceWhenThereAreNoWarnings(t *testing.T) {
	installDefaultAppTestHooks(t)

	warningWriteCalls := 0
	var gotWarnings []model.Warning
	writeWarnings = func(warnings []model.Warning) error {
		warningWriteCalls++
		gotWarnings = append([]model.Warning(nil), warnings...)
		return nil
	}

	config := Config{Namespace: "default", PodName: "risk-pod", WriteJSON: true}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if warningWriteCalls != 1 {
		t.Fatalf("expected writeWarnings to be called once even when warnings are empty, got %d", warningWriteCalls)
	}
	if len(gotWarnings) != 0 {
		t.Fatalf("expected empty warnings slice, got %#v", gotWarnings)
	}
}

func TestRunWritesWarningsWhenScanHasWarningsButNoFindings(t *testing.T) {
	installDefaultAppTestHooks(t)

	analyzeSnapshot = func(snapshot model.Snapshot) []model.Signal {
		return nil
	}
	doSnapshot = func(metadata model.Metadata) (model.Snapshot, error) {
		return model.Snapshot{
			Metadata: metadata,
			Warnings: []string{
				"snapshot warning",
			},
		}, nil
	}
	var gotFindings []*model.Finding
	var gotWarnings []model.Warning
	writeFindings = func(findings []*model.Finding) error {
		gotFindings = append([]*model.Finding(nil), findings...)
		return nil
	}
	writeWarnings = func(warnings []model.Warning) error {
		gotWarnings = append([]model.Warning(nil), warnings...)
		return nil
	}

	config := Config{Namespace: "default", PodName: "risk-pod", WriteJSON: true}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if config.ScannedContainers != 1 {
		t.Fatalf("expected successful zero-finding scan, got scanned=%d", config.ScannedContainers)
	}
	if len(gotFindings) != 0 {
		t.Fatalf("expected no findings to be written, got %#v", gotFindings)
	}
	if len(gotWarnings) != 1 {
		t.Fatalf("expected one warning to be written, got %#v", gotWarnings)
	}
	if gotWarnings[0].ContainerName != "app" || gotWarnings[0].Stage != "collect" {
		t.Fatalf("unexpected warning context %#v", gotWarnings[0])
	}
}

func TestRunWritesWarningsWhenAllContainersAreSkipped(t *testing.T) {
	installDefaultAppTestHooks(t)

	resolvePod = func(namespace, podName string) (target.PodTarget, error) {
		return target.PodTarget{
			Namespace: namespace,
			Name:      podName,
			NodeName:  "worker-1",
			Containers: []target.ContainerTarget{
				{Name: "app", ContainerID: "containerd://app123", Runtime: "containerd", RuntimeID: "app123"},
				{Name: "sidecar", ContainerID: "containerd://sidecar456", Runtime: "containerd", RuntimeID: "sidecar456"},
			},
		}, nil
	}
	resolveContainerPID = func(containerID string) (int, error) {
		return 0, errors.New("crictl endpoint unavailable")
	}

	var gotWarnings []model.Warning
	writeWarnings = func(warnings []model.Warning) error {
		gotWarnings = append([]model.Warning(nil), warnings...)
		return nil
	}

	config := Config{Namespace: "default", PodName: "risk-pod", WriteJSON: true}
	err := config.Run()
	if err == nil {
		t.Fatal("expected all-skipped scan to fail")
	}
	if !strings.Contains(err.Error(), "no containers were scanned successfully") {
		t.Fatalf("expected no-containers error, got %v", err)
	}
	if len(gotWarnings) != 2 {
		t.Fatalf("expected warnings to be written for both skipped containers, got %#v", gotWarnings)
	}
	for _, warning := range gotWarnings {
		if warning.Stage != "resolve-pid" || !strings.Contains(warning.Message, "crictl endpoint unavailable") {
			t.Fatalf("unexpected warning %#v", warning)
		}
	}
}

func TestRunWritesFindingsAndWarningsOnceAfterPodAggregation(t *testing.T) {
	installDefaultAppTestHooks(t)

	resolvePod = func(namespace, podName string) (target.PodTarget, error) {
		return target.PodTarget{
			Namespace: namespace,
			Name:      podName,
			NodeName:  "worker-1",
			Containers: []target.ContainerTarget{
				{Name: "app", ContainerID: "containerd://app123", Runtime: "containerd", RuntimeID: "app123"},
				{Name: "sidecar", ContainerID: "containerd://sidecar456", Runtime: "containerd", RuntimeID: "sidecar456"},
			},
		}, nil
	}
	doSnapshot = func(metadata model.Metadata) (model.Snapshot, error) {
		return model.Snapshot{
			Metadata: metadata,
			Warnings: []string{
				"warning for " + metadata.ContainerName,
			},
		}, nil
	}
	writeFindingCalls := 0
	writeWarningCalls := 0
	var gotWarnings []model.Warning
	writeFindings = func(findings []*model.Finding) error {
		writeFindingCalls++
		if len(findings) != 2 {
			t.Fatalf("expected aggregated findings for two containers, got %#v", findings)
		}
		return nil
	}
	writeWarnings = func(warnings []model.Warning) error {
		writeWarningCalls++
		gotWarnings = append([]model.Warning(nil), warnings...)
		return nil
	}

	config := Config{Namespace: "default", PodName: "risk-pod", WriteJSON: true}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if writeFindingCalls != 1 {
		t.Fatalf("expected findings to be written once after aggregation, got %d", writeFindingCalls)
	}
	if writeWarningCalls != 1 {
		t.Fatalf("expected warnings to be written once after aggregation, got %d", writeWarningCalls)
	}
	if len(gotWarnings) != 2 {
		t.Fatalf("expected two aggregated warnings, got %#v", gotWarnings)
	}
	if gotWarnings[0].ContainerName == gotWarnings[1].ContainerName {
		t.Fatalf("expected warnings from different containers, got %#v", gotWarnings)
	}
}

func TestRunAppendsPodCompositionAfterAllContainersAreScanned(t *testing.T) {
	installDefaultAppTestHooks(t)

	resolvePod = func(namespace, podName string) (target.PodTarget, error) {
		return target.PodTarget{
			Namespace: namespace,
			Name:      podName,
			NodeName:  "worker-1",
			Containers: []target.ContainerTarget{
				{Name: "debugger", ContainerID: "containerd://debugger", Runtime: "containerd", RuntimeID: "debugger"},
				{Name: "app", ContainerID: "containerd://app", Runtime: "containerd", RuntimeID: "app"},
			},
		}, nil
	}
	doSnapshot = func(metadata model.Metadata) (model.Snapshot, error) {
		return model.Snapshot{Metadata: metadata}, nil
	}

	composeCalls := 0
	composePodFindings = func(analyses []analyze.PodContainerAnalysis) []*model.Finding {
		composeCalls++
		if len(analyses) != 2 {
			t.Fatalf("expected composition to receive both scanned containers, got %#v", analyses)
		}
		if analyses[0].Snapshot.ContainerName != "debugger" || analyses[1].Snapshot.ContainerName != "app" {
			t.Fatalf("expected composition to receive per-container snapshots in scan order, got %#v", analyses)
		}
		return []*model.Finding{
			{
				Category:  "composition",
				RiskLevel: analyze.HighRisk,
				Title:     "synthetic pod composition",
				Namespace: namespaceFromAnalyses(analyses),
				PodName:   analyses[0].Snapshot.PodName,
				NodeName:  analyses[0].Snapshot.NodeName,
			},
		}
	}

	config := Config{Namespace: "default", PodName: "risk-pod"}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if composeCalls != 1 {
		t.Fatalf("expected composition to run once after aggregation, got %d", composeCalls)
	}
	if len(config.Findings) != 3 {
		t.Fatalf("expected two primitive findings plus one composition finding, got %#v", config.Findings)
	}
	if config.Findings[0].Category != "composition" {
		t.Fatalf("expected composition finding to be included in final sorted findings, got %#v", config.Findings)
	}
}

func namespaceFromAnalyses(analyses []analyze.PodContainerAnalysis) string {
	if len(analyses) == 0 {
		return ""
	}
	return analyses[0].Snapshot.Namespace
}

func TestRunPropagatesWarningWriteError(t *testing.T) {
	installDefaultAppTestHooks(t)

	doSnapshot = func(metadata model.Metadata) (model.Snapshot, error) {
		return model.Snapshot{
			Metadata: metadata,
			Warnings: []string{"snapshot warning"},
		}, nil
	}
	writeWarnings = func([]model.Warning) error {
		return errors.New("warning write failed")
	}

	config := Config{Namespace: "default", PodName: "risk-pod", WriteJSON: true}
	err := config.Run()
	if err == nil {
		t.Fatal("expected warning write error")
	}
	if !strings.Contains(err.Error(), "warning write failed") {
		t.Fatalf("expected warning write error to propagate, got %v", err)
	}
}

func TestRunDoesNotWriteWarningsWhenFindingWriteFails(t *testing.T) {
	installDefaultAppTestHooks(t)

	doSnapshot = func(metadata model.Metadata) (model.Snapshot, error) {
		return model.Snapshot{
			Metadata: metadata,
			Warnings: []string{"snapshot warning"},
		}, nil
	}
	warningWriteCalls := 0
	writeFindings = func([]*model.Finding) error {
		return errors.New("finding write failed")
	}
	writeWarnings = func([]model.Warning) error {
		warningWriteCalls++
		return nil
	}

	config := Config{Namespace: "default", PodName: "risk-pod", WriteJSON: true}
	err := config.Run()
	if err == nil {
		t.Fatal("expected finding write error")
	}
	if !strings.Contains(err.Error(), "finding write failed") {
		t.Fatalf("expected finding write error to propagate, got %v", err)
	}
	if warningWriteCalls != 0 {
		t.Fatalf("expected warnings not to be written after finding write failure, got %d calls", warningWriteCalls)
	}
}

func TestRunRealWritersCreateCategoryAndWarningFilesAfterAggregation(t *testing.T) {
	installDefaultAppTestHooks(t)

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

	doSnapshot = func(metadata model.Metadata) (model.Snapshot, error) {
		return model.Snapshot{
			Metadata: metadata,
			Warnings: []string{
				"snapshot warning",
			},
		}, nil
	}
	writeFindings = func(findings []*model.Finding) error {
		if err := report.WriteFindingsAsJSON(report.CompositionFindings); err != nil {
			return err
		}
		if err := report.WriteFindingsAsJSON(report.CapabilitiesFindings); err != nil {
			return err
		}
		if err := report.WriteFindingsAsJSON(report.NamespaceFindings); err != nil {
			return err
		}
		if err := report.WriteFindingsAsJSON(report.MountFindings); err != nil {
			return err
		}
		return report.WriteFindingsAsJSON(report.SeccompFindings)
	}
	writeWarnings = report.WriteWarningsAsJSON

	config := Config{Namespace: "default", PodName: "risk-pod", WriteJSON: true}
	if err := config.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	seccompData, err := os.ReadFile(filepath.Join(tmp, "seccomp.json"))
	if err != nil {
		t.Fatalf("expected seccomp.json to be written: %v", err)
	}
	var findings []model.Finding
	if err := json.Unmarshal(seccompData, &findings); err != nil {
		t.Fatalf("unmarshal seccomp.json: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one seccomp finding, got %#v", findings)
	}
	if findings[0].Namespace != "default" || findings[0].PodName != "risk-pod" || len(findings[0].Containers) != 1 {
		t.Fatalf("expected finding context in seccomp.json, got %#v", findings[0])
	}

	warningData, err := os.ReadFile(filepath.Join(tmp, "warnings.json"))
	if err != nil {
		t.Fatalf("expected warnings.json to be written: %v", err)
	}
	var warnings []model.Warning
	if err := json.Unmarshal(warningData, &warnings); err != nil {
		t.Fatalf("unmarshal warnings.json: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected one warning, got %#v", warnings)
	}
	if warnings[0].Namespace != "default" || warnings[0].PodName != "risk-pod" || warnings[0].ContainerName != "app" {
		t.Fatalf("expected warning context in warnings.json, got %#v", warnings[0])
	}
}
