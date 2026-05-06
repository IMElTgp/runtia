package report

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/analyze"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("copy stdout: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}
	return buf.String()
}

func withTempWorkingDir(t *testing.T) string {
	t.Helper()

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir tempdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})
	return tmp
}

func jsonSampleFinding(category string, risk int, title string) *model.Finding {
	return &model.Finding{
		Category:       category,
		RiskLevel:      risk,
		Title:          title,
		Summary:        "summary for " + title,
		Evidence:       []string{"evidence for " + title},
		Recommendation: "recommend " + title,
		RelativeThreads: []*target.Thread{{
			Tgid:         10,
			Tid:          11,
			Comm:         "worker\n",
			IsMainThread: true,
		}},
		RelativeNS: &target.NSRef{Type: "user", Dev: 1, Ino: 2},
		MountPoint: []string{"/" + category},
	}
}

func representativeFinding(category string, risk int, title string, tgid, tid int) *model.Finding {
	f := jsonSampleFinding(category, risk, title)
	f.RelativeThreads = []*target.Thread{{
		Tgid:         tgid,
		Tid:          tid,
		Comm:         title + "\n",
		IsMainThread: tid == tgid,
	}}
	switch category {
	case "namespace":
		f.RelativeNS = &target.NSRef{Type: "user", Dev: uint64(tgid), Ino: uint64(tid)}
		f.MountPoint = nil
	case "mount":
		f.RelativeNS = nil
		f.MountPoint = []string{"/" + title}
	default:
		f.MountPoint = nil
	}
	return f
}

func TestGenerateFindingsCopiesSignalFields(t *testing.T) {
	thread := &target.Thread{Tgid: 10, Tid: 10, Comm: "main"}
	ns := &target.NSRef{Type: "pid", Dev: 4, Ino: 5}
	signals := []model.Signal{
		{
			Finding: model.Finding{
				Category:        "seccomp",
				RiskLevel:       analyze.HighRisk,
				Title:           "seccomp title",
				Summary:         "seccomp summary",
				Evidence:        []string{"line1", "line2"},
				RelativeThreads: []*target.Thread{thread},
				RelativeNS:      ns,
				MountPoint:      []string{"/run"},
				Recommendation:  "keep seccomp",
			},
		},
	}

	findings := GenerateFindings(signals)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	got := findings[0]
	if got.Category != "seccomp" || got.RiskLevel != analyze.HighRisk || got.Title != "seccomp title" {
		t.Fatalf("unexpected generated finding metadata: %#v", got)
	}
	if got.Summary != "seccomp summary" || got.Recommendation != "keep seccomp" {
		t.Fatalf("unexpected generated finding text fields: %#v", got)
	}
	if len(got.Evidence) != 2 || got.Evidence[0] != "line1" || got.RelativeThreads[0] != thread || got.RelativeNS != ns {
		t.Fatalf("unexpected generated finding evidence/relations: %#v", got)
	}
}

func TestFindingsToJSONReturnsIndentedHomogeneousJSONArray(t *testing.T) {
	findings := []*model.Finding{
		jsonSampleFinding("namespace", analyze.Fatal, "first"),
		jsonSampleFinding("namespace", analyze.HighRisk, "second"),
	}

	jsons, err, typ := findingsToJSON(findings)
	if err != nil {
		t.Fatalf("FindingsToJSON() error = %v", err)
	}
	if typ != "namespace" {
		t.Fatalf("expected namespace type, got %q", typ)
	}
	if !strings.Contains(string(jsons), "\n ") {
		t.Fatalf("expected indented JSON output, got %q", string(jsons))
	}

	var decoded []model.Finding
	if err := json.Unmarshal(jsons, &decoded); err != nil {
		t.Fatalf("unmarshal findings json: %v", err)
	}
	if len(decoded) != 2 || decoded[0].Category != "namespace" || decoded[1].Title != "second" {
		t.Fatalf("unexpected decoded json payload: %#v", decoded)
	}
}

func TestFindingsToJSONRejectsEmptySlice(t *testing.T) {
	jsons, err, typ := findingsToJSON(nil)
	if err == nil {
		t.Fatalf("expected error for empty findings")
	}
	if jsons != nil || typ != "" {
		t.Fatalf("expected nil json and empty type on error, got json=%v type=%q", jsons, typ)
	}
}

func TestWriteFindingsAsJSONCreatesAndOverwritesPerCategoryFile(t *testing.T) {
	tmp := withTempWorkingDir(t)

	first := []*model.Finding{jsonSampleFinding("namespace", analyze.Fatal, "first")}
	second := []*model.Finding{jsonSampleFinding("namespace", analyze.HighRisk, "second")}

	if err := WriteFindingsAsJSON(first); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteFindingsAsJSON(second); err != nil {
		t.Fatalf("second write: %v", err)
	}

	path := filepath.Join(tmp, "namespace.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read namespace.json: %v", err)
	}

	var decoded []model.Finding
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("expected valid json file, got %q: %v", string(raw), err)
	}
	if len(decoded) != 1 || decoded[0].Title != "second" {
		t.Fatalf("expected second write to replace file contents, got %#v", decoded)
	}
	if strings.Contains(string(raw), "first") {
		t.Fatalf("expected truncated rewrite without stale content, got %q", string(raw))
	}
}

func TestWriteFindingsAsJSONCreatesExpectedFilePerCategory(t *testing.T) {
	tmp := withTempWorkingDir(t)

	cases := []struct {
		category string
		fileName string
	}{
		{category: "namespace", fileName: "namespace.json"},
		{category: "mount", fileName: "mount.json"},
		{category: "seccomp", fileName: "seccomp.json"},
		{category: "capabilities", fileName: "capabilities.json"},
	}

	for _, tc := range cases {
		if err := WriteFindingsAsJSON([]*model.Finding{jsonSampleFinding(tc.category, analyze.HighRisk, tc.category)}); err != nil {
			t.Fatalf("write %s findings: %v", tc.category, err)
		}

		path := filepath.Join(tmp, tc.fileName)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", tc.fileName, err)
		}
		var decoded []model.Finding
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("unmarshal %s: %v", tc.fileName, err)
		}
		if len(decoded) != 1 || decoded[0].Category != tc.category {
			t.Fatalf("unexpected file content for %s: %#v", tc.fileName, decoded)
		}
	}
}

func TestPrintToTerminalShowsSummaryAndRepresentativeHighRiskFindings(t *testing.T) {
	resetSortState(t)

	findings := []*model.Finding{
		representativeFinding("namespace", analyze.Fatal, "ns-fatal-1", 1, 1),
		representativeFinding("namespace", analyze.HighRisk, "ns-high-2", 1, 2),
		representativeFinding("namespace", analyze.HighRisk, "ns-high-3", 1, 3),
		representativeFinding("seccomp", analyze.HighRisk, "sec-high-1", 2, 2),
		representativeFinding("seccomp", analyze.HighRisk, "sec-high-2", 2, 3),
		representativeFinding("capabilities", analyze.HighRisk, "Thread has CAP_BPF in its effective capability set", 3, 3),
		representativeFinding("capabilities", analyze.HighRisk, "Thread has CAP_SYS_ADMIN in its effective capability set", 3, 4),
		representativeFinding("mount", analyze.HighRisk, "mount-high-1", 4, 4),
		representativeFinding("mount", analyze.LowRisk, "mount-low", 4, 5),
	}

	out := captureStdout(t, func() {
		PrintToTerminal(findings)
	})

	for _, want := range []string{
		"Findings Summary:",
		"Fatal: 1",
		"HighRisk: 7",
		"LowRisk: 1",
		"Representative Fatal/HighRisk Findings:",
		"[1/6]",
		"[6/6]",
		"ns-fatal-1",
		"ns-high-2",
		"sec-high-1",
		"sec-high-2",
		"CAP_BPF",
		"CAP_SYS_ADMIN",
		"See all findings in ./namespace.json, ./mount.json, ./seccomp.json or ./capabilities.json.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected terminal output to contain %q, got:\n%s", want, out)
		}
	}

	for _, notWant := range []string{
		"ns-high-3",
		"mount-high-1",
		"mount-low",
	} {
		if strings.Contains(out, notWant) {
			t.Fatalf("did not expect terminal output to contain %q, got:\n%s", notWant, out)
		}
	}
}

func TestPrintToTerminalHandlesNoRepresentativeHighRiskFindings(t *testing.T) {
	resetSortState(t)

	out := captureStdout(t, func() {
		PrintToTerminal([]*model.Finding{
			representativeFinding("mount", analyze.MediumRisk, "medium-only", 1, 1),
			representativeFinding("seccomp", analyze.LowRisk, "low-only", 2, 2),
		})
	})

	if !strings.Contains(out, "No Fatal/HighRisk findings to highlight in terminal.") {
		t.Fatalf("expected no-high-risk notice, got:\n%s", out)
	}
	if strings.Contains(out, "Representative Fatal/HighRisk Findings:") {
		t.Fatalf("did not expect representative findings section, got:\n%s", out)
	}
}

func TestPrintToTerminalHandlesEmptyInput(t *testing.T) {
	resetSortState(t)

	out := captureStdout(t, func() {
		PrintToTerminal(nil)
	})
	if strings.TrimSpace(out) != "No findings." {
		t.Fatalf("unexpected empty-input output %q", out)
	}
}
