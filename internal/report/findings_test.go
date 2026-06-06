package report

import (
	"reflect"
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/analyze"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

func TestGenerateFindingsSkipsCoveredPrimitiveSignalsAndKeepsCompositionSignals(t *testing.T) {
	thread := &target.Thread{Tid: 10, Tgid: 10, Comm: "main", IsMainThread: true}
	ns := &target.NSRef{Type: "pid", Dev: 1, Ino: 2}
	relatedNamespaces := []target.NSRef{
		{Type: "mnt", Dev: 3, Ino: 4},
		{Type: "mnt", Dev: 5, Ino: 6},
	}
	signals := []model.Signal{
		{
			Finding: model.Finding{
				Category:        "seccomp",
				RiskLevel:       analyze.HighRisk,
				Title:           "covered primitive",
				RelativeThreads: []*target.Thread{thread},
			},
			Covered: true,
		},
		{
			Finding: model.Finding{
				Category:        "mount",
				RiskLevel:       analyze.MediumRisk,
				Title:           "standalone primitive",
				RelativeThreads: []*target.Thread{thread},
				MountPoint:      []string{"/etc"},
			},
		},
		{
			Finding: model.Finding{
				Category:        "composition",
				RiskLevel:       analyze.Fatal,
				Title:           "composition finding",
				Summary:         "combined signal",
				Evidence:        []string{"cap", "mount"},
				RelativeThreads: []*target.Thread{thread},
				RelativeNS:      ns,
				RelativeNSs:     relatedNamespaces,
			},
		},
	}

	findings := GenerateFindings(signals)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings after skipping covered signals, got %d", len(findings))
	}
	if findings[0].Title != "standalone primitive" || findings[1].Title != "composition finding" {
		t.Fatalf("unexpected findings %#v", findings)
	}
	if findings[1].Category != "composition" || findings[1].RelativeNS != ns {
		t.Fatalf("expected composition finding to keep metadata, got %#v", findings[1])
	}
	if !reflect.DeepEqual(findings[1].RelativeNSs, relatedNamespaces) {
		t.Fatalf("expected composition finding to keep related namespaces, got %#v", findings[1].RelativeNSs)
	}
}

func TestGenerateFindingsPreservesPodAndContainerContext(t *testing.T) {
	thread := &target.Thread{Tid: 20, Tgid: 20, Comm: "main", IsMainThread: true}
	container := model.ContainerContext{
		Name:        "app",
		ContainerID: "containerd://app123",
		Runtime:     "containerd",
		RuntimeID:   "app123",
		InitPID:     1234,
		CgroupPath:  "/sys/fs/cgroup/app",
	}
	signals := []model.Signal{
		{
			Finding: model.Finding{
				Category:        "seccomp",
				RiskLevel:       analyze.HighRisk,
				Title:           "context signal",
				Namespace:       "default",
				PodName:         "risk-pod",
				NodeName:        "worker-1",
				Containers:      []model.ContainerContext{container},
				Evidence:        []string{"pod=default/risk-pod", "container name=app"},
				RelativeThreads: []*target.Thread{thread},
			},
		},
	}

	findings := GenerateFindings(signals)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	got := findings[0]
	if got.Namespace != "default" || got.PodName != "risk-pod" || got.NodeName != "worker-1" {
		t.Fatalf("expected pod context to be preserved, got %#v", got)
	}
	if len(got.Containers) != 1 || !reflect.DeepEqual(got.Containers[0], container) {
		t.Fatalf("expected container context to be preserved, got %#v", got.Containers)
	}
	if len(got.Evidence) != 2 || got.Evidence[0] != "pod=default/risk-pod" || got.Evidence[1] != "container name=app" {
		t.Fatalf("expected context evidence to be preserved, got %#v", got.Evidence)
	}
	if len(got.RelativeThreads) != 1 || got.RelativeThreads[0] != thread {
		t.Fatalf("expected thread relation to remain backward compatible, got %#v", got.RelativeThreads)
	}
}

func TestGenerateFindingsWithEmptyContextRemainsBackwardCompatible(t *testing.T) {
	thread := &target.Thread{Tid: 30, Tgid: 30, Comm: "legacy", IsMainThread: true}
	signals := []model.Signal{
		{
			Finding: model.Finding{
				Category:        "mount",
				RiskLevel:       analyze.MediumRisk,
				Title:           "legacy context-free signal",
				Evidence:        []string{"mount=/host"},
				RelativeThreads: []*target.Thread{thread},
			},
		},
	}

	findings := GenerateFindings(signals)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	got := findings[0]
	if got.Namespace != "" || got.PodName != "" || got.NodeName != "" {
		t.Fatalf("expected empty pod context to remain empty, got %#v", got)
	}
	if len(got.Containers) != 0 {
		t.Fatalf("expected no container context, got %#v", got.Containers)
	}
	if len(got.Evidence) != 1 || got.Evidence[0] != "mount=/host" {
		t.Fatalf("expected evidence to remain unchanged, got %#v", got.Evidence)
	}
	if len(got.RelativeThreads) != 1 || got.RelativeThreads[0] != thread {
		t.Fatalf("expected thread relation to remain unchanged, got %#v", got.RelativeThreads)
	}
}
