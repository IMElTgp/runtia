package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMetadataCarriesPodAndContainerContext(t *testing.T) {
	collectedAt := time.Unix(1700000000, 0)
	metadata := Metadata{
		CollectedAt:   collectedAt,
		Namespace:     "default",
		PodName:       "risk-pod",
		NodeName:      "worker-1",
		ContainerName: "app",
		ContainerID:   "containerd://app123",
		Runtime:       "containerd",
		RuntimeID:     "app123",
		InitPID:       1234,
		CgroupPath:    "/sys/fs/cgroup/kubepods/pod/app",
	}

	var snapshot Snapshot
	snapshot.collectMetadata(metadata)

	if snapshot.CollectedAt != collectedAt {
		t.Fatalf("expected collectedAt %v, got %v", collectedAt, snapshot.CollectedAt)
	}
	if snapshot.Namespace != "default" {
		t.Fatalf("expected namespace default, got %q", snapshot.Namespace)
	}
	if snapshot.PodName != "risk-pod" {
		t.Fatalf("expected pod risk-pod, got %q", snapshot.PodName)
	}
	if snapshot.NodeName != "worker-1" {
		t.Fatalf("expected node worker-1, got %q", snapshot.NodeName)
	}
	if snapshot.ContainerName != "app" {
		t.Fatalf("expected container app, got %q", snapshot.ContainerName)
	}
	if snapshot.ContainerID != "containerd://app123" {
		t.Fatalf("expected container ID containerd://app123, got %q", snapshot.ContainerID)
	}
	if snapshot.Runtime != "containerd" {
		t.Fatalf("expected runtime containerd, got %q", snapshot.Runtime)
	}
	if snapshot.RuntimeID != "app123" {
		t.Fatalf("expected runtime ID app123, got %q", snapshot.RuntimeID)
	}
	if snapshot.InitPID != 1234 {
		t.Fatalf("expected init PID 1234, got %d", snapshot.InitPID)
	}
	if snapshot.CgroupPath != "/sys/fs/cgroup/kubepods/pod/app" {
		t.Fatalf("expected cgroup path to be copied, got %q", snapshot.CgroupPath)
	}
}

func TestMetadataPreservesLegacyContainerIDOnlyContext(t *testing.T) {
	metadata := Metadata{
		ContainerID: "legacy-container",
		InitPID:     12,
		CgroupPath:  "/sys/fs/cgroup/legacy",
	}

	var snapshot Snapshot
	snapshot.collectMetadata(metadata)

	if snapshot.ContainerID != "legacy-container" {
		t.Fatalf("expected legacy container ID to remain supported, got %q", snapshot.ContainerID)
	}
	if snapshot.InitPID != 12 {
		t.Fatalf("expected init PID 12, got %d", snapshot.InitPID)
	}
	if snapshot.CgroupPath != "/sys/fs/cgroup/legacy" {
		t.Fatalf("expected cgroup path to remain supported, got %q", snapshot.CgroupPath)
	}
	if snapshot.Namespace != "" || snapshot.PodName != "" || snapshot.NodeName != "" {
		t.Fatalf("expected pod fields to be optional for legacy metadata, got namespace=%q pod=%q node=%q", snapshot.Namespace, snapshot.PodName, snapshot.NodeName)
	}
}

func TestContainerContextFromMetadata(t *testing.T) {
	metadata := Metadata{
		ContainerName: "app",
		ContainerID:   "containerd://app123",
		Runtime:       "containerd",
		RuntimeID:     "app123",
		InitPID:       1234,
		CgroupPath:    "/sys/fs/cgroup/app",
	}

	got := ContainerContextFromMetadata(metadata)

	if got.Name != "app" {
		t.Fatalf("expected name app, got %q", got.Name)
	}
	if got.ContainerID != "containerd://app123" {
		t.Fatalf("expected full container ID, got %q", got.ContainerID)
	}
	if got.Runtime != "containerd" {
		t.Fatalf("expected runtime containerd, got %q", got.Runtime)
	}
	if got.RuntimeID != "app123" {
		t.Fatalf("expected runtime ID app123, got %q", got.RuntimeID)
	}
	if got.InitPID != 1234 {
		t.Fatalf("expected init PID 1234, got %d", got.InitPID)
	}
	if got.CgroupPath != "/sys/fs/cgroup/app" {
		t.Fatalf("expected cgroup path, got %q", got.CgroupPath)
	}
}

func TestAttachContextToFindingsAddsStructuredContextAndEvidence(t *testing.T) {
	metadata := Metadata{
		Namespace:     "default",
		PodName:       "risk-pod",
		NodeName:      "worker-1",
		ContainerName: "app",
		ContainerID:   "containerd://app123",
		Runtime:       "containerd",
		RuntimeID:     "app123",
		InitPID:       1234,
		CgroupPath:    "/sys/fs/cgroup/app",
	}
	findings := []*Finding{
		{
			Category: "seccomp",
			Title:    "Thread runs without seccomp filtering",
			Evidence: []string{"SeccompMode=0"},
		},
	}

	AttachContextToFindings(findings, metadata)

	finding := findings[0]
	if finding.Namespace != "default" || finding.PodName != "risk-pod" || finding.NodeName != "worker-1" {
		t.Fatalf("expected pod context to be attached, got namespace=%q pod=%q node=%q", finding.Namespace, finding.PodName, finding.NodeName)
	}
	if len(finding.Containers) != 1 {
		t.Fatalf("expected one container context, got %#v", finding.Containers)
	}
	if finding.Containers[0].Name != "app" || finding.Containers[0].ContainerID != "containerd://app123" {
		t.Fatalf("unexpected container context %#v", finding.Containers[0])
	}
	joinedEvidence := strings.Join(finding.Evidence, "\n")
	if !strings.Contains(joinedEvidence, "pod=default/risk-pod") {
		t.Fatalf("expected evidence to include readable pod context, got %#v", finding.Evidence)
	}
	if !strings.Contains(joinedEvidence, "container name=app") || !strings.Contains(joinedEvidence, "id=containerd://app123") || !strings.Contains(joinedEvidence, "init_pid=1234") {
		t.Fatalf("expected evidence to include readable container context, got %#v", finding.Evidence)
	}
	if finding.Evidence[len(finding.Evidence)-1] != "SeccompMode=0" {
		t.Fatalf("expected original evidence to be preserved after context evidence, got %#v", finding.Evidence)
	}
}

func TestAttachContextToFindingsAppliesToMultipleFindingsAndSkipsNil(t *testing.T) {
	metadata := Metadata{
		Namespace:     "default",
		PodName:       "risk-pod",
		NodeName:      "worker-1",
		ContainerName: "app",
		ContainerID:   "containerd://app123",
		Runtime:       "containerd",
		RuntimeID:     "app123",
		InitPID:       1234,
		CgroupPath:    "/sys/fs/cgroup/app",
	}
	findings := []*Finding{
		{
			Category: "seccomp",
			Title:    "seccomp finding",
			Evidence: []string{"SeccompMode=0"},
		},
		nil,
		{
			Category: "capabilities",
			Title:    "capability finding",
			Evidence: []string{"CapEff includes CAP_SYS_ADMIN"},
		},
	}

	AttachContextToFindings(findings, metadata)

	for _, idx := range []int{0, 2} {
		finding := findings[idx]
		if finding.Namespace != "default" || finding.PodName != "risk-pod" || finding.NodeName != "worker-1" {
			t.Fatalf("finding %d missing pod context: %#v", idx, finding)
		}
		if len(finding.Containers) != 1 {
			t.Fatalf("finding %d expected one container context, got %#v", idx, finding.Containers)
		}
		if finding.Containers[0].Name != "app" || finding.Containers[0].RuntimeID != "app123" {
			t.Fatalf("finding %d unexpected container context %#v", idx, finding.Containers[0])
		}
		if !strings.Contains(strings.Join(finding.Evidence, "\n"), "pod=default/risk-pod") {
			t.Fatalf("finding %d missing readable pod evidence %#v", idx, finding.Evidence)
		}
	}
	if findings[0].Evidence[len(findings[0].Evidence)-1] != "SeccompMode=0" {
		t.Fatalf("expected first finding original evidence to remain last, got %#v", findings[0].Evidence)
	}
	if findings[2].Evidence[len(findings[2].Evidence)-1] != "CapEff includes CAP_SYS_ADMIN" {
		t.Fatalf("expected second finding original evidence to remain last, got %#v", findings[2].Evidence)
	}
}

func TestAttachContextToFindingsDoesNotDuplicateExistingContainerContext(t *testing.T) {
	metadata := Metadata{
		Namespace:     "default",
		PodName:       "risk-pod",
		NodeName:      "worker-1",
		ContainerName: "app",
		ContainerID:   "containerd://app123",
		Runtime:       "containerd",
		RuntimeID:     "app123",
		InitPID:       1234,
	}
	findings := []*Finding{
		{
			Category:   "composition",
			Title:      "cross-container finding",
			Namespace:  "default",
			PodName:    "risk-pod",
			NodeName:   "worker-1",
			Containers: []ContainerContext{ContainerContextFromMetadata(metadata)},
			Evidence:   []string{"existing evidence"},
		},
	}

	AttachContextToFindings(findings, metadata)

	if len(findings[0].Containers) != 1 {
		t.Fatalf("expected existing matching container context not to be duplicated, got %#v", findings[0].Containers)
	}
	if findings[0].Evidence[0] != "existing evidence" {
		t.Fatalf("expected existing context-rich finding evidence not to be rewritten, got %#v", findings[0].Evidence)
	}
}

func TestAttachContextToFindingsIsIdempotent(t *testing.T) {
	metadata := Metadata{
		Namespace:     "default",
		PodName:       "risk-pod",
		NodeName:      "worker-1",
		ContainerName: "app",
		ContainerID:   "containerd://app123",
		Runtime:       "containerd",
		RuntimeID:     "app123",
		InitPID:       1234,
	}
	findings := []*Finding{
		{
			Category: "mount",
			Title:    "mount finding",
			Evidence: []string{"mount=/host"},
		},
	}

	AttachContextToFindings(findings, metadata)
	AttachContextToFindings(findings, metadata)

	if len(findings[0].Containers) != 1 {
		t.Fatalf("expected context attach to be idempotent for containers, got %#v", findings[0].Containers)
	}

	podEvidenceCount := 0
	containerEvidenceCount := 0
	for _, evidence := range findings[0].Evidence {
		if strings.Contains(evidence, "pod=default/risk-pod") {
			podEvidenceCount++
		}
		if strings.Contains(evidence, "container name=app") {
			containerEvidenceCount++
		}
	}
	if podEvidenceCount != 1 || containerEvidenceCount != 1 {
		t.Fatalf("expected context evidence to be added once, got pod=%d container=%d evidence=%#v", podEvidenceCount, containerEvidenceCount, findings[0].Evidence)
	}
}

func TestAttachContextToFindingsAddsDifferentContainerContext(t *testing.T) {
	existingContainer := ContainerContext{
		Name:        "app",
		ContainerID: "containerd://app123",
		Runtime:     "containerd",
		RuntimeID:   "app123",
		InitPID:     1234,
	}
	metadata := Metadata{
		Namespace:     "default",
		PodName:       "risk-pod",
		NodeName:      "worker-1",
		ContainerName: "sidecar",
		ContainerID:   "containerd://sidecar456",
		Runtime:       "containerd",
		RuntimeID:     "sidecar456",
		InitPID:       5678,
	}
	findings := []*Finding{
		{
			Category:   "composition",
			Title:      "cross-container finding",
			Namespace:  "default",
			PodName:    "risk-pod",
			NodeName:   "worker-1",
			Containers: []ContainerContext{existingContainer},
			Evidence:   []string{"existing cross-container evidence"},
		},
	}

	AttachContextToFindings(findings, metadata)

	if len(findings[0].Containers) != 2 {
		t.Fatalf("expected different container context to be appended, got %#v", findings[0].Containers)
	}
	if !reflect.DeepEqual(findings[0].Containers[0], existingContainer) {
		t.Fatalf("expected existing container context to keep position, got %#v", findings[0].Containers)
	}
	if findings[0].Containers[1].Name != "sidecar" || findings[0].Containers[1].RuntimeID != "sidecar456" {
		t.Fatalf("expected sidecar context to be appended, got %#v", findings[0].Containers[1])
	}
	if findings[0].Evidence[len(findings[0].Evidence)-1] != "existing cross-container evidence" {
		t.Fatalf("expected original evidence to remain after appended context evidence, got %#v", findings[0].Evidence)
	}
	joinedEvidence := strings.Join(findings[0].Evidence, "\n")
	if !strings.Contains(joinedEvidence, "container name=sidecar") {
		t.Fatalf("expected appended container context evidence, got %#v", findings[0].Evidence)
	}
}

func TestAttachContextToFindingsWithEmptyMetadataIsNoop(t *testing.T) {
	findings := []*Finding{
		{
			Category: "namespace",
			Title:    "namespace finding",
			Evidence: []string{"existing evidence"},
		},
	}

	AttachContextToFindings(findings, Metadata{})

	if findings[0].Namespace != "" || findings[0].PodName != "" || findings[0].NodeName != "" {
		t.Fatalf("expected empty metadata not to set pod context, got %#v", findings[0])
	}
	if len(findings[0].Containers) != 0 {
		t.Fatalf("expected empty metadata not to add container context, got %#v", findings[0].Containers)
	}
	if len(findings[0].Evidence) != 1 || findings[0].Evidence[0] != "existing evidence" {
		t.Fatalf("expected evidence to remain unchanged for empty metadata, got %#v", findings[0].Evidence)
	}
}

func TestAttachContextToFindingsPartialMetadataEvidence(t *testing.T) {
	cases := []struct {
		name                  string
		metadata              Metadata
		wantEvidenceFragments []string
		wantAbsentFragments   []string
	}{
		{
			name: "namespace and pod without node",
			metadata: Metadata{
				Namespace:     "default",
				PodName:       "risk-pod",
				ContainerName: "app",
			},
			wantEvidenceFragments: []string{"pod=default/risk-pod", "container name=app"},
			wantAbsentFragments:   []string{"node=", "id=", "init_pid="},
		},
		{
			name: "pod without namespace",
			metadata: Metadata{
				PodName:       "risk-pod",
				ContainerName: "app",
			},
			wantEvidenceFragments: []string{"pod=/risk-pod", "container name=app"},
			wantAbsentFragments:   []string{"node=", "id=", "init_pid="},
		},
		{
			name: "container name without pod context",
			metadata: Metadata{
				ContainerName: "app",
			},
			wantEvidenceFragments: []string{"container name=app"},
			wantAbsentFragments:   []string{"pod=", "id=", "runtime=", "init_pid="},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := []*Finding{
				{
					Category: "seccomp",
					Title:    "partial context",
					Evidence: []string{"original evidence"},
				},
			}

			AttachContextToFindings(findings, tc.metadata)
			joinedEvidence := strings.Join(findings[0].Evidence, "\n")

			for _, fragment := range tc.wantEvidenceFragments {
				if !strings.Contains(joinedEvidence, fragment) {
					t.Fatalf("expected evidence to contain %q, got %#v", fragment, findings[0].Evidence)
				}
			}
			for _, fragment := range tc.wantAbsentFragments {
				if strings.Contains(joinedEvidence, fragment) {
					t.Fatalf("expected evidence not to contain %q, got %#v", fragment, findings[0].Evidence)
				}
			}
			if findings[0].Evidence[len(findings[0].Evidence)-1] != "original evidence" {
				t.Fatalf("expected original evidence to remain last, got %#v", findings[0].Evidence)
			}
		})
	}
}

func TestFindingContextJSONIsOptionalAndBackwardCompatible(t *testing.T) {
	legacy := Finding{
		Category: "mount",
		Title:    "legacy finding",
		Evidence: []string{"mount evidence"},
	}

	legacyJSON, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy finding: %v", err)
	}
	var legacyMap map[string]any
	if err := json.Unmarshal(legacyJSON, &legacyMap); err != nil {
		t.Fatalf("unmarshal legacy finding: %v", err)
	}
	if _, ok := legacyMap["Namespace"]; ok {
		t.Fatalf("expected empty Namespace to be omitted from legacy JSON, got %s", legacyJSON)
	}
	if _, ok := legacyMap["Containers"]; ok {
		t.Fatalf("expected empty Containers to be omitted from legacy JSON, got %s", legacyJSON)
	}

	withContext := Finding{
		Category:  "seccomp",
		Title:     "context finding",
		Namespace: "default",
		PodName:   "risk-pod",
		NodeName:  "worker-1",
		Containers: []ContainerContext{
			{
				Name:        "app",
				ContainerID: "containerd://app123",
				Runtime:     "containerd",
				RuntimeID:   "app123",
				InitPID:     1234,
				CgroupPath:  "/sys/fs/cgroup/app",
			},
		},
	}

	contextJSON, err := json.Marshal(withContext)
	if err != nil {
		t.Fatalf("marshal context finding: %v", err)
	}
	var contextMap map[string]any
	if err := json.Unmarshal(contextJSON, &contextMap); err != nil {
		t.Fatalf("unmarshal context finding: %v", err)
	}
	if contextMap["Namespace"] != "default" || contextMap["PodName"] != "risk-pod" || contextMap["NodeName"] != "worker-1" {
		t.Fatalf("expected pod context fields in JSON, got %s", contextJSON)
	}
	if _, ok := contextMap["Containers"]; !ok {
		t.Fatalf("expected container context in JSON, got %s", contextJSON)
	}
}

func TestWarningJSONContainsPodAndContainerContext(t *testing.T) {
	warning := Warning{
		Namespace:     "default",
		PodName:       "risk-pod",
		NodeName:      "worker-1",
		ContainerName: "sidecar",
		ContainerID:   "containerd://sidecar456",
		Stage:         "resolve",
		Message:       "container has no containerID after one retry; skipped",
	}

	data, err := json.Marshal(warning)
	if err != nil {
		t.Fatalf("marshal warning: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal warning: %v", err)
	}

	if got["Namespace"] != "default" {
		t.Fatalf("expected namespace in warning JSON, got %s", data)
	}
	if got["PodName"] != "risk-pod" {
		t.Fatalf("expected pod in warning JSON, got %s", data)
	}
	if got["NodeName"] != "worker-1" {
		t.Fatalf("expected node in warning JSON, got %s", data)
	}
	if got["ContainerName"] != "sidecar" || got["ContainerID"] != "containerd://sidecar456" {
		t.Fatalf("expected container context in warning JSON, got %s", data)
	}
	if got["Stage"] != "resolve" || got["Message"] == "" {
		t.Fatalf("expected warning stage and message in JSON, got %s", data)
	}
}

func TestContainerContextJSONOmitsEmptyFields(t *testing.T) {
	container := ContainerContext{Name: "app"}

	data, err := json.Marshal(container)
	if err != nil {
		t.Fatalf("marshal container context: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal container context: %v", err)
	}

	if got["Name"] != "app" {
		t.Fatalf("expected Name to be present, got %s", data)
	}
	for _, field := range []string{"ContainerID", "Runtime", "RuntimeID", "InitPID", "CgroupPath"} {
		if _, ok := got[field]; ok {
			t.Fatalf("expected empty %s to be omitted, got %s", field, data)
		}
	}
}

func TestWarningJSONOmitsEmptyFields(t *testing.T) {
	warning := Warning{
		Stage:   "resolve",
		Message: "container skipped",
	}

	data, err := json.Marshal(warning)
	if err != nil {
		t.Fatalf("marshal warning: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal warning: %v", err)
	}

	if got["Stage"] != "resolve" || got["Message"] != "container skipped" {
		t.Fatalf("expected stage and message to remain, got %s", data)
	}
	for _, field := range []string{"Namespace", "PodName", "NodeName", "ContainerName", "ContainerID"} {
		if _, ok := got[field]; ok {
			t.Fatalf("expected empty %s to be omitted, got %s", field, data)
		}
	}
}
