package report

import (
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/analyze"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

func TestGenerateFindingsSkipsCoveredPrimitiveSignalsAndKeepsCompositionSignals(t *testing.T) {
	thread := &target.Thread{Tid: 10, Tgid: 10, Comm: "main", IsMainThread: true}
	ns := &target.NSRef{Type: "pid", Dev: 1, Ino: 2}
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
}
