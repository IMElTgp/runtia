package report

import (
	"slices"
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/analyze"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

func testThread(tgid, tid int) *target.Thread {
	return &target.Thread{Tgid: tgid, Tid: tid}
}

func testNS(nsType string, dev, ino uint64) *target.NSRef {
	return &target.NSRef{Type: nsType, Dev: dev, Ino: ino}
}

func resetSortState(t *testing.T) {
	t.Helper()
	NamespaceFindings = nil
	SeccompFindings = nil
	MountFindings = nil
	CapabilitiesFindings = nil
	t.Cleanup(func() {
		NamespaceFindings = nil
		SeccompFindings = nil
		MountFindings = nil
		CapabilitiesFindings = nil
	})
}

func capabilityFinding(risk int, capName string, tgid, tid int, evidence ...string) *model.Finding {
	if len(evidence) == 0 {
		evidence = []string{"capability=" + capName}
	}
	return &model.Finding{
		Category:        "capabilities",
		RiskLevel:       risk,
		Title:           "Thread has " + capName + " in its effective capability set",
		Evidence:        evidence,
		RelativeThreads: []*target.Thread{testThread(tgid, tid)},
	}
}

func seccompFinding(risk, tgid, tid int, evidence ...string) *model.Finding {
	if len(evidence) == 0 {
		evidence = []string{"tid"}
	}
	return &model.Finding{
		Category:        "seccomp",
		RiskLevel:       risk,
		Title:           "seccomp",
		Evidence:        evidence,
		RelativeThreads: []*target.Thread{testThread(tgid, tid)},
	}
}

func namespaceFinding(risk int, nsType string, dev, ino uint64, evidence ...string) *model.Finding {
	if len(evidence) == 0 {
		evidence = []string{"ns"}
	}
	return &model.Finding{
		Category:   "namespace",
		RiskLevel:  risk,
		Title:      "namespace",
		Evidence:   evidence,
		RelativeNS: testNS(nsType, dev, ino),
	}
}

func mountFinding(risk int, title string, mountPoints []string, evidence ...string) *model.Finding {
	if len(evidence) == 0 {
		evidence = []string{"mount"}
	}
	return &model.Finding{
		Category:   "mount",
		RiskLevel:  risk,
		Title:      title,
		Evidence:   evidence,
		MountPoint: mountPoints,
	}
}

func findingsHaveSamePointers(got, want []*model.Finding) bool {
	return slices.EqualFunc(got, want, func(a, b *model.Finding) bool { return a == b })
}

func namespaceSignatures(findings []*model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.RelativeNS.Type+":"+finding.Evidence[0])
	}
	return out
}

func mountSignatures(findings []*model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.Title+":"+finding.Evidence[0])
	}
	return out
}

func globalSignatures(findings []*model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.Category+":"+finding.Title)
	}
	return out
}

func TestRemoveDuplicatesUsesRiskTitleAndNormalizedEvidence(t *testing.T) {
	first := mountFinding(analyze.HighRisk, "duplicate", []string{"/etc"}, "line-b", "line-a")
	duplicate := mountFinding(analyze.HighRisk, "duplicate", []string{"/tmp"}, "line-a", "line-b")
	differentRisk := mountFinding(analyze.MediumRisk, "duplicate", []string{"/etc"}, "line-a", "line-b")
	differentTitle := mountFinding(analyze.HighRisk, "other", []string{"/etc"}, "line-a", "line-b")

	got := removeDuplicates([]*model.Finding{first, duplicate, differentRisk, differentTitle})

	if len(got) != 3 {
		t.Fatalf("expected 3 findings after deduplication, got %d", len(got))
	}
	if !slices.Contains(got, duplicate) {
		t.Fatalf("expected dedup to keep one representative of duplicate findings")
	}
	if !slices.Contains(got, differentRisk) || !slices.Contains(got, differentTitle) {
		t.Fatalf("expected non-duplicates to remain after deduplication")
	}
}

func TestNsTypeRank(t *testing.T) {
	user := testNS("user", 1, 1)
	pid := testNS("pid", 1, 2)
	mnt := testNS("mnt", 1, 3)

	if !nsTypeRank(user, pid) {
		t.Fatalf("expected user namespace to sort before pid namespace")
	}
	if !nsTypeRank(pid, mnt) {
		t.Fatalf("expected pid namespace to sort before mount namespace")
	}
	if nsTypeRank(mnt, pid) {
		t.Fatalf("expected mount namespace not to sort before pid namespace")
	}
	if !nsTypeRank(user, nil) {
		t.Fatalf("expected non-nil namespace to sort before nil")
	}
	if nsTypeRank(nil, user) {
		t.Fatalf("expected nil namespace not to sort before non-nil")
	}
}

func TestSortNamespaceFindingsOrdersByRiskTypeDevAndIno(t *testing.T) {
	resetSortState(t)

	highUserDev2 := namespaceFinding(analyze.HighRisk, "user", 2, 30, "u2")
	highUserDev1Ino20 := namespaceFinding(analyze.HighRisk, "user", 1, 20, "u1-20")
	highUserDev1Ino10 := namespaceFinding(analyze.HighRisk, "user", 1, 10, "u1-10")
	highPid := namespaceFinding(analyze.HighRisk, "pid", 1, 5, "pid")
	highMnt := namespaceFinding(analyze.HighRisk, "mnt", 1, 1, "mnt")
	mediumUser := namespaceFinding(analyze.MediumRisk, "user", 0, 1, "medium")
	duplicate := namespaceFinding(analyze.HighRisk, "user", 1, 10, "u1-10")
	duplicate.Title = highUserDev1Ino10.Title

	NamespaceFindings = []*model.Finding{
		mediumUser,
		highMnt,
		highUserDev2,
		highPid,
		highUserDev1Ino20,
		highUserDev1Ino10,
		duplicate,
	}

	sortNamespaceFindings()

	want := []string{
		"user:u1-10",
		"user:u1-20",
		"user:u2",
		"pid:pid",
		"mnt:mnt",
		"user:medium",
	}
	if got := namespaceSignatures(NamespaceFindings); !slices.Equal(got, want) {
		t.Fatalf("unexpected namespace finding order: got %v want %v", got, want)
	}
}

func TestSortSeccompFindingsOrdersByRiskThenThread(t *testing.T) {
	resetSortState(t)

	highTgid1Tid2 := seccompFinding(analyze.HighRisk, 1, 2, "b")
	highTgid1Tid1 := seccompFinding(analyze.HighRisk, 1, 1, "a")
	highTgid2Tid1 := seccompFinding(analyze.HighRisk, 2, 1, "c")
	medium := seccompFinding(analyze.MediumRisk, 0, 9, "d")
	duplicate := seccompFinding(analyze.HighRisk, 9, 9, "a")
	duplicate.Title = highTgid1Tid1.Title

	SeccompFindings = []*model.Finding{highTgid2Tid1, medium, duplicate, highTgid1Tid2, highTgid1Tid1}
	sortSeccompFindings()

	want := []*model.Finding{highTgid1Tid1, highTgid1Tid2, highTgid2Tid1, medium}
	if !findingsHaveSamePointers(SeccompFindings, want) {
		t.Fatalf("unexpected seccomp finding order: got %#v", SeccompFindings)
	}
}

func TestSortMountFindingsOrdersByRiskThenNormalizedMountPoint(t *testing.T) {
	resetSortState(t)

	highEtc := mountFinding(analyze.HighRisk, "etc", []string{"/etc"}, "a")
	highDevVar := mountFinding(analyze.HighRisk, "dev-var", []string{"/var/run", "/dev"}, "b")
	highRun := mountFinding(analyze.HighRisk, "run", []string{"/run"}, "c")
	medium := mountFinding(analyze.MediumRisk, "medium", []string{"/a"}, "d")
	duplicate := mountFinding(analyze.HighRisk, "run", []string{"/run"}, "c")

	MountFindings = []*model.Finding{medium, highRun, duplicate, highDevVar, highEtc}
	sortMountFindings()

	want := []string{"dev-var:b", "etc:a", "run:c", "medium:d"}
	if got := mountSignatures(MountFindings); !slices.Equal(got, want) {
		t.Fatalf("unexpected mount finding order: got %v want %v", got, want)
	}
}

func TestSortCapabilitiesFindingsOrdersByRiskCapabilityAndThread(t *testing.T) {
	resetSortState(t)

	highAudit := capabilityFinding(analyze.HighRisk, "CAP_AUDIT_WRITE", 2, 1, "a")
	highBpfTgid1Tid2 := capabilityFinding(analyze.HighRisk, "CAP_BPF", 1, 2, "b")
	highBpfTgid1Tid1 := capabilityFinding(analyze.HighRisk, "CAP_BPF", 1, 1, "c")
	highBpfTgid2Tid1 := capabilityFinding(analyze.HighRisk, "CAP_BPF", 2, 1, "d")
	medium := capabilityFinding(analyze.MediumRisk, "CAP_SYS_TIME", 1, 9, "e")
	duplicate := capabilityFinding(analyze.HighRisk, "CAP_BPF", 9, 9, "c")

	CapabilitiesFindings = []*model.Finding{
		medium,
		highBpfTgid2Tid1,
		duplicate,
		highAudit,
		highBpfTgid1Tid2,
		highBpfTgid1Tid1,
	}
	sortCapabilitiesFindings()

	want := []*model.Finding{
		highAudit,
		highBpfTgid1Tid1,
		highBpfTgid1Tid2,
		highBpfTgid2Tid1,
		medium,
	}
	if !findingsHaveSamePointers(CapabilitiesFindings, want) {
		t.Fatalf("unexpected capabilities finding order: got %#v", CapabilitiesFindings)
	}
}

func TestSortFindingsOrdersByRiskCategoryAndTitle(t *testing.T) {
	namespace := namespaceFinding(analyze.HighRisk, "user", 1, 1, "n")
	namespace.Title = "b-title"
	capability := capabilityFinding(analyze.HighRisk, "CAP_BPF", 1, 1, "c")
	capability.Title = "a-title"
	mount := mountFinding(analyze.HighRisk, "c-title", []string{"/run"}, "m")
	seccomp := seccompFinding(analyze.MediumRisk, 1, 1, "s")
	seccomp.Title = "d-title"
	duplicate := mountFinding(analyze.HighRisk, "c-title", []string{"/run"}, "m")

	got := SortFindings([]*model.Finding{seccomp, mount, duplicate, namespace, capability})

	want := []string{
		"capabilities:a-title",
		"mount:c-title",
		"namespace:b-title",
		"seccomp:d-title",
	}
	if actual := globalSignatures(got); !slices.Equal(actual, want) {
		t.Fatalf("unexpected global finding order: got %v want %v", actual, want)
	}
}

func TestSortFindingsByCategoryResetsAndPopulatesEachCategory(t *testing.T) {
	resetSortState(t)

	firstBatch := []*model.Finding{
		namespaceFinding(analyze.HighRisk, "pid", 1, 2, "ns-old"),
		seccompFinding(analyze.HighRisk, 1, 2, "sec-old"),
		mountFinding(analyze.HighRisk, "mount-old", []string{"/run"}, "mount-old"),
		capabilityFinding(analyze.HighRisk, "CAP_SYS_ADMIN", 1, 2, "cap-old"),
	}
	SortFindingsByCategory(firstBatch)

	secondNamespace := namespaceFinding(analyze.HighRisk, "user", 1, 1, "ns-new")
	secondSeccomp := seccompFinding(analyze.HighRisk, 2, 3, "sec-new")
	secondMount := mountFinding(analyze.MediumRisk, "mount-new", []string{"/etc"}, "mount-new")
	secondCapability := capabilityFinding(analyze.HighRisk, "CAP_AUDIT_WRITE", 2, 3, "cap-new")
	SortFindingsByCategory([]*model.Finding{secondMount, secondCapability, secondSeccomp, secondNamespace})

	if len(NamespaceFindings) != 1 || NamespaceFindings[0] != secondNamespace {
		t.Fatalf("expected namespace findings to be reset and refilled, got %#v", NamespaceFindings)
	}
	if len(SeccompFindings) != 1 || SeccompFindings[0] != secondSeccomp {
		t.Fatalf("expected seccomp findings to be reset and refilled, got %#v", SeccompFindings)
	}
	if len(MountFindings) != 1 || MountFindings[0] != secondMount {
		t.Fatalf("expected mount findings to be reset and refilled, got %#v", MountFindings)
	}
	if len(CapabilitiesFindings) != 1 || CapabilitiesFindings[0] != secondCapability {
		t.Fatalf("expected capabilities findings to be reset and refilled, got %#v", CapabilitiesFindings)
	}
}
