package report

import (
	"encoding/json"
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/analyze"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

func TestFindingsToJSONIncludesContextFieldsWhenPresent(t *testing.T) {
	findings := []*model.Finding{
		{
			Category:  "seccomp",
			RiskLevel: analyze.HighRisk,
			Title:     "context finding",
			Namespace: "default",
			PodName:   "risk-pod",
			NodeName:  "worker-1",
			Containers: []model.ContainerContext{
				{
					Name:        "app",
					ContainerID: "containerd://app123",
					Runtime:     "containerd",
					RuntimeID:   "app123",
					InitPID:     1234,
					CgroupPath:  "/sys/fs/cgroup/app",
				},
			},
			Evidence: []string{"pod=default/risk-pod", "container name=app"},
		},
	}

	data, err, category := findingsToJSON(findings)
	if err != nil {
		t.Fatalf("findingsToJSON() error = %v", err)
	}
	if category != "seccomp" {
		t.Fatalf("expected category seccomp, got %q", category)
	}

	var decoded []map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal findings JSON: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected one finding in JSON, got %#v", decoded)
	}
	finding := decoded[0]
	if finding["Namespace"] != "default" || finding["PodName"] != "risk-pod" || finding["NodeName"] != "worker-1" {
		t.Fatalf("expected pod context fields in JSON, got %s", data)
	}
	containers, ok := finding["Containers"].([]any)
	if !ok || len(containers) != 1 {
		t.Fatalf("expected one container context in JSON, got %s", data)
	}
	container, ok := containers[0].(map[string]any)
	if !ok {
		t.Fatalf("expected container JSON object, got %#v", containers[0])
	}
	if container["Name"] != "app" || container["ContainerID"] != "containerd://app123" || container["RuntimeID"] != "app123" {
		t.Fatalf("unexpected container context JSON: %s", data)
	}
}

func TestFindingsToJSONOmitEmptyContextFieldsForLegacyFindings(t *testing.T) {
	findings := []*model.Finding{
		{
			Category:  "mount",
			RiskLevel: analyze.MediumRisk,
			Title:     "legacy finding",
			Evidence:  []string{"mount=/host"},
		},
	}

	data, err, category := findingsToJSON(findings)
	if err != nil {
		t.Fatalf("findingsToJSON() error = %v", err)
	}
	if category != "mount" {
		t.Fatalf("expected category mount, got %q", category)
	}

	var decoded []map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal findings JSON: %v", err)
	}
	if _, ok := decoded[0]["Namespace"]; ok {
		t.Fatalf("expected empty Namespace to be omitted from legacy JSON, got %s", data)
	}
	if _, ok := decoded[0]["PodName"]; ok {
		t.Fatalf("expected empty PodName to be omitted from legacy JSON, got %s", data)
	}
	if _, ok := decoded[0]["NodeName"]; ok {
		t.Fatalf("expected empty NodeName to be omitted from legacy JSON, got %s", data)
	}
	if _, ok := decoded[0]["Containers"]; ok {
		t.Fatalf("expected empty Containers to be omitted from legacy JSON, got %s", data)
	}
	if _, ok := decoded[0]["RelativeNSs"]; ok {
		t.Fatalf("expected empty RelativeNSs to be omitted from legacy JSON, got %s", data)
	}
}

func TestFindingsToJSONOmitsEmptyContainerContextFields(t *testing.T) {
	findings := []*model.Finding{
		{
			Category:  "composition",
			RiskLevel: analyze.HighRisk,
			Title:     "partial container context",
			Namespace: "default",
			PodName:   "risk-pod",
			Containers: []model.ContainerContext{
				{Name: "app"},
			},
		},
	}

	data, err, category := findingsToJSON(findings)
	if err != nil {
		t.Fatalf("findingsToJSON() error = %v", err)
	}
	if category != "composition" {
		t.Fatalf("expected category composition, got %q", category)
	}

	var decoded []map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal findings JSON: %v", err)
	}
	containers, ok := decoded[0]["Containers"].([]any)
	if !ok || len(containers) != 1 {
		t.Fatalf("expected one container context in JSON, got %s", data)
	}
	container, ok := containers[0].(map[string]any)
	if !ok {
		t.Fatalf("expected container JSON object, got %#v", containers[0])
	}
	if container["Name"] != "app" {
		t.Fatalf("expected container name app, got %s", data)
	}
	for _, field := range []string{"ContainerID", "Runtime", "RuntimeID", "InitPID", "CgroupPath"} {
		if _, ok := container[field]; ok {
			t.Fatalf("expected empty %s to be omitted, got %s", field, data)
		}
	}
}

func TestFindingsToJSONIncludesMultipleRelatedNamespaces(t *testing.T) {
	findings := []*model.Finding{
		{
			Category:  "composition",
			RiskLevel: analyze.HighRisk,
			Title:     "shared volume finding",
			RelativeNSs: []target.NSRef{
				{Type: "mnt", Dev: 10, Ino: 100},
				{Type: "mnt", Dev: 20, Ino: 200},
			},
		},
	}

	data, err, category := findingsToJSON(findings)
	if err != nil {
		t.Fatalf("findingsToJSON() error = %v", err)
	}
	if category != "composition" {
		t.Fatalf("expected category composition, got %q", category)
	}

	var decoded []map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal findings JSON: %v", err)
	}
	namespaces, ok := decoded[0]["RelativeNSs"].([]any)
	if !ok || len(namespaces) != 2 {
		t.Fatalf("expected two related namespaces in JSON, got %s", data)
	}
	first := namespaces[0].(map[string]any)
	second := namespaces[1].(map[string]any)
	if first["Type"] != "mnt" || first["Dev"] != float64(10) || first["Ino"] != float64(100) {
		t.Fatalf("unexpected first related namespace JSON: %s", data)
	}
	if second["Type"] != "mnt" || second["Dev"] != float64(20) || second["Ino"] != float64(200) {
		t.Fatalf("unexpected second related namespace JSON: %s", data)
	}
}
