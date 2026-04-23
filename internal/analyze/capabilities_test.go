package analyze

import (
	"reflect"
	"strings"
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

var capabilityNames = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_DAC_READ_SEARCH",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETPCAP",
	"CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE",
	"CAP_NET_BROADCAST",
	"CAP_NET_ADMIN",
	"CAP_NET_RAW",
	"CAP_IPC_LOCK",
	"CAP_IPC_OWNER",
	"CAP_SYS_MODULE",
	"CAP_SYS_RAWIO",
	"CAP_SYS_CHROOT",
	"CAP_SYS_PTRACE",
	"CAP_SYS_PACCT",
	"CAP_SYS_ADMIN",
	"CAP_SYS_BOOT",
	"CAP_SYS_NICE",
	"CAP_SYS_RESOURCE",
	"CAP_SYS_TIME",
	"CAP_SYS_TTY_CONFIG",
	"CAP_MKNOD",
	"CAP_LEASE",
	"CAP_AUDIT_WRITE",
	"CAP_AUDIT_CONTROL",
	"CAP_SETFCAP",
	"CAP_MAC_OVERRIDE",
	"CAP_MAC_ADMIN",
	"CAP_SYSLOG",
	"CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND",
	"CAP_AUDIT_READ",
	"CAP_PERFMON",
	"CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

func capBit(cap int) uint64 {
	return uint64(1) << uint(cap)
}

func allKnownCapsMask() uint64 {
	var mask uint64
	for i := range capabilityNames {
		mask |= capBit(i)
	}
	return mask
}

func capabilityTestThread(mntNS target.NSRef) *target.Thread {
	mask := allKnownCapsMask()
	return &target.Thread{
		Tid:          101,
		Tgid:         100,
		Comm:         " cap-worker \n",
		IsMainThread: false,
		UserNS:       target.NSRef{Type: "user", Dev: 11, Ino: 111},
		MntNS:        mntNS,
		PIDNS:        target.NSRef{Type: "pid", Dev: 22, Ino: 222},
		CapEff:       mask,
		CapPrm:       mask,
		CapInh:       mask,
		CapAmb:       mask,
		CapBnd:       mask,
	}
}

func baseCapabilitySignal(risk int, thread *target.Thread) *model.Signal {
	return &model.Signal{
		Finding: model.Finding{
			Category:        "capabilities",
			RiskLevel:       risk,
			RelativeThreads: []*target.Thread{thread},
		},
	}
}

func TestCapabilityMetadataFunctions(t *testing.T) {
	cases := []struct {
		name    string
		capType string
		label   string
		field   string
		context string
	}{
		{
			name:    "effective",
			capType: "eff",
			label:   "effective",
			field:   "CapEff",
			context: "This capability is active for current kernel permission checks.",
		},
		{
			name:    "permitted",
			capType: "prm",
			label:   "permitted",
			field:   "CapPrm",
			context: "It is not necessarily active, but it is available for the thread to make effective.",
		},
		{
			name:    "ambient",
			capType: "amb",
			label:   "ambient",
			field:   "CapAmb",
			context: "It may be preserved across execve and passed to non-privileged programs.",
		},
		{
			name:    "inheritable",
			capType: "inh",
			label:   "inheritable",
			field:   "CapInh",
			context: "It may participate in capability inheritance across execve when file capability rules allow it.",
		},
		{
			name:    "bounding",
			capType: "bnd",
			label:   "bounding",
			field:   "CapBnd",
			context: "It remains in the bounding set, so it has not been removed from the capabilities that can be gained across execve.",
		},
		{
			name:    "custom",
			capType: "custom",
			label:   "custom",
			field:   "Capcustom",
			context: "This capability is present on the thread.",
		},
	}

	thread := &target.Thread{
		CapEff: 1,
		CapPrm: 2,
		CapInh: 3,
		CapAmb: 4,
		CapBnd: 5,
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := capabilitySetLabel(tc.capType); got != tc.label {
				t.Fatalf("expected label %q, got %q", tc.label, got)
			}
			if got := capabilitySetField(tc.capType); got != tc.field {
				t.Fatalf("expected field %q, got %q", tc.field, got)
			}
			if got := capabilitySetContext(tc.capType); got != tc.context {
				t.Fatalf("expected context %q, got %q", tc.context, got)
			}
		})
	}

	if got := concerningCap(thread, "eff"); got != 1 {
		t.Fatalf("expected CapEff 1, got %d", got)
	}
	if got := concerningCap(thread, "prm"); got != 2 {
		t.Fatalf("expected CapPrm 2, got %d", got)
	}
	if got := concerningCap(thread, "inh"); got != 3 {
		t.Fatalf("expected CapInh 3, got %d", got)
	}
	if got := concerningCap(thread, "amb"); got != 4 {
		t.Fatalf("expected CapAmb 4, got %d", got)
	}
	if got := concerningCap(thread, "bnd"); got != 5 {
		t.Fatalf("expected CapBnd 5, got %d", got)
	}
	if got := concerningCap(thread, "unknown"); got != 0 {
		t.Fatalf("expected unknown cap type to return 0, got %d", got)
	}

	if got := formatNSRef(target.NSRef{}); got != "unknown" {
		t.Fatalf("expected unknown namespace marker, got %q", got)
	}
	if got := formatNSRef(target.NSRef{Type: "mnt", Dev: 12, Ino: 34}); got != "mnt:12:34" {
		t.Fatalf("unexpected namespace formatting %q", got)
	}
}

func TestCapabilityRecommendationHelpers(t *testing.T) {
	if got := capabilitySetRecommendation("eff", "CAP_SYS_ADMIN"); got != "Drop CAP_SYS_ADMIN from CapEff unless the workload has a reviewed, narrow need for it." {
		t.Fatalf("unexpected effective recommendation %q", got)
	}
	if got := capabilitySetRecommendation("prm", "CAP_SYS_ADMIN"); got != "Remove CAP_SYS_ADMIN from CapPrm so the thread cannot make it effective later." {
		t.Fatalf("unexpected permitted recommendation %q", got)
	}
	if got := capabilitySetRecommendation("amb", "CAP_SYS_ADMIN"); got != "Remove CAP_SYS_ADMIN from CapAmb so it cannot survive execve into non-privileged programs." {
		t.Fatalf("unexpected ambient recommendation %q", got)
	}
	if got := capabilitySetRecommendation("inh", "CAP_SYS_ADMIN"); got != "Remove CAP_SYS_ADMIN from CapInh unless a reviewed file-capability exec path requires it." {
		t.Fatalf("unexpected inheritable recommendation %q", got)
	}
	if got := capabilitySetRecommendation("bnd", "CAP_SYS_ADMIN"); got != "Drop CAP_SYS_ADMIN from CapBnd so it cannot be regained through execve or file capabilities." {
		t.Fatalf("unexpected bounding recommendation %q", got)
	}
	if got := capabilitySetRecommendation("other", "CAP_SYS_ADMIN"); got != "Remove CAP_SYS_ADMIN unless it is explicitly required." {
		t.Fatalf("unexpected default recommendation %q", got)
	}

	highRisk := &model.Signal{Finding: model.Finding{RiskLevel: HighRisk}}
	got := capabilityCommonRecommendation(highRisk, "eff", "CAP_SYS_ADMIN", "Keep mounts read-only.", "mount composition matters.")
	if !strings.Contains(got, "Drop CAP_SYS_ADMIN from CapEff") {
		t.Fatalf("expected base recommendation in %q", got)
	}
	if !strings.Contains(got, "Keep mounts read-only.") {
		t.Fatalf("expected hardening guidance in %q", got)
	}
	if !strings.Contains(got, "For ordinary application containers") {
		t.Fatalf("expected high-risk exception text in %q", got)
	}
	if !strings.Contains(got, "Keep seccomp filtering enabled") {
		t.Fatalf("expected seccomp hardening text in %q", got)
	}
	if !strings.Contains(got, "Check possible composite exposure: mount composition matters.") {
		t.Fatalf("expected composite guidance in %q", got)
	}

	bounding := &model.Signal{Finding: model.Finding{RiskLevel: MediumRisk}}
	got = capabilityCommonRecommendation(bounding, "bnd", "CAP_NET_ADMIN", "Keep network namespaces private.", "host networking matters.")
	if strings.Contains(got, "Keep seccomp filtering enabled") {
		t.Fatalf("did not expect seccomp sentence for bounding set recommendation: %q", got)
	}
}

func TestCapabilitySignalHelpers(t *testing.T) {
	if got := setCapabilityText(nil, "eff", "CAP_CHOWN", "impact"); got != nil {
		t.Fatalf("expected nil signal to stay nil")
	}
	addCapabilityEvidence(nil, "eff", "CAP_CHOWN")
	if got := setCapabilityDetails(nil, "eff", "CAP_CHOWN", "impact", "hardening", "composite"); got != nil {
		t.Fatalf("expected nil signal to stay nil")
	}

	noThread := &model.Signal{}
	addCapabilityEvidence(noThread, "eff", "CAP_CHOWN")
	if len(noThread.Evidence) != 1 || noThread.Evidence[0] != "CAP_CHOWN is present in CapEff" {
		t.Fatalf("unexpected no-thread evidence %#v", noThread.Evidence)
	}

	thread := capabilityTestThread(target.NSRef{Type: "mnt", Dev: 1, Ino: 2})
	signal := &model.Signal{
		Finding: model.Finding{
			RiskLevel:       HighRisk,
			RelativeThreads: []*target.Thread{thread},
		},
	}

	got := setCapabilityDetails(signal, "eff", "CAP_CHOWN", "It changes ownership.", "Keep host mounts read-only.", "writable host mounts matter.")
	if got != signal {
		t.Fatalf("expected helper to mutate original signal")
	}
	if got.Title != "Thread has CAP_CHOWN in its effective capability set" {
		t.Fatalf("unexpected title %q", got.Title)
	}
	if !strings.Contains(got.Summary, capabilitySetContext("eff")) || !strings.Contains(got.Summary, "It changes ownership.") {
		t.Fatalf("unexpected summary %q", got.Summary)
	}
	if len(got.Evidence) != 3 {
		t.Fatalf("expected 3 evidence lines, got %#v", got.Evidence)
	}
	if !strings.Contains(got.Evidence[0], `comm="cap-worker"`) {
		t.Fatalf("expected trimmed comm in evidence, got %q", got.Evidence[0])
	}
	if !strings.Contains(got.Evidence[1], "CapEff=0x") || !strings.Contains(got.Evidence[1], "includes CAP_CHOWN") {
		t.Fatalf("unexpected capability evidence line %q", got.Evidence[1])
	}
	if !strings.Contains(got.Evidence[2], "userns=user:11:111") || !strings.Contains(got.Evidence[2], "mntns=mnt:1:2") || !strings.Contains(got.Evidence[2], "pidns=pid:22:222") {
		t.Fatalf("unexpected namespace evidence line %q", got.Evidence[2])
	}
	if !strings.Contains(got.Recommendation, "Drop CAP_CHOWN from CapEff") ||
		!strings.Contains(got.Recommendation, "Keep host mounts read-only.") ||
		!strings.Contains(got.Recommendation, "For ordinary application containers") ||
		!strings.Contains(got.Recommendation, "Keep seccomp filtering enabled") ||
		!strings.Contains(got.Recommendation, "Check possible composite exposure: writable host mounts matter.") {
		t.Fatalf("unexpected recommendation %q", got.Recommendation)
	}
}

func TestSwitchCapabilitiesCoversAllHandlers(t *testing.T) {
	if len(capabilityNames) != len(capThreatLevels) {
		t.Fatalf("expected capability names and threat levels to stay aligned, got %d names and %d risks", len(capabilityNames), len(capThreatLevels))
	}
	if CAP_CHECKPOINT_RESTORE != len(capabilityNames)-1 {
		t.Fatalf("expected final capability index %d, got %d", len(capabilityNames)-1, CAP_CHECKPOINT_RESTORE)
	}

	thread := capabilityTestThread(target.NSRef{Type: "mnt", Dev: 3, Ino: 4})
	for cap, capName := range capabilityNames {
		t.Run(capName, func(t *testing.T) {
			signal := baseCapabilitySignal(capThreatLevels[cap], thread)

			got := switchCapabilities(cap, signal, "prm")
			if got != signal {
				t.Fatalf("expected switchCapabilities to mutate original signal")
			}

			wantTitle := "Thread has " + capName + " in its permitted capability set"
			if got.Title != wantTitle {
				t.Fatalf("expected title %q, got %q", wantTitle, got.Title)
			}
			if !strings.Contains(got.Summary, capName) {
				t.Fatalf("expected summary to mention %s, got %q", capName, got.Summary)
			}
			if !strings.Contains(got.Summary, capabilitySetContext("prm")) {
				t.Fatalf("expected summary to include permitted context, got %q", got.Summary)
			}

			if len(got.Evidence) != 3 {
				t.Fatalf("expected 3 evidence lines, got %#v", got.Evidence)
			}
			evidence := strings.Join(got.Evidence, "\n")
			if !strings.Contains(evidence, "CapPrm=0x") {
				t.Fatalf("expected permitted evidence line in %#v", got.Evidence)
			}
			if !strings.Contains(evidence, capName) {
				t.Fatalf("expected evidence to mention %s in %#v", capName, got.Evidence)
			}

			if !strings.Contains(got.Recommendation, capabilitySetRecommendation("prm", capName)) {
				t.Fatalf("expected recommendation to include base advice for %s, got %q", capName, got.Recommendation)
			}
			if !strings.Contains(got.Recommendation, "Check possible composite exposure:") {
				t.Fatalf("expected composite guidance in %q", got.Recommendation)
			}

			hasException := strings.Contains(got.Recommendation, "For ordinary application containers")
			if want := capThreatLevels[cap] >= HighRisk; hasException != want {
				t.Fatalf("expected exception text=%t for risk %d, got %q", want, capThreatLevels[cap], got.Recommendation)
			}
			hasSeccomp := strings.Contains(got.Recommendation, "Keep seccomp filtering enabled")
			if want := capThreatLevels[cap] >= MediumRisk; hasSeccomp != want {
				t.Fatalf("expected seccomp text=%t for risk %d, got %q", want, capThreatLevels[cap], got.Recommendation)
			}
		})
	}
}

func TestSwitchCapabilitiesUnknownCapabilityReturnsInput(t *testing.T) {
	signal := &model.Signal{Finding: model.Finding{Title: "unchanged", Summary: "still here"}}

	got := switchCapabilities(len(capabilityNames), signal, "eff")
	if got != signal {
		t.Fatalf("expected unknown capability to return original signal")
	}
	if got.Title != "unchanged" || got.Summary != "still here" {
		t.Fatalf("expected signal to remain unchanged, got %#v", got)
	}
}

func TestDowngradeRiskLevel(t *testing.T) {
	cases := []struct {
		name       string
		capability uint64
		risk       int
		capType    string
		want       int
	}{
		{
			name:       "effective-keeps-risk",
			capability: CAP_CHOWN,
			risk:       LowRisk,
			capType:    "eff",
			want:       LowRisk,
		},
		{
			name:       "permitted-downgrades-to-info",
			capability: CAP_CHOWN,
			risk:       LowRisk,
			capType:    "prm",
			want:       Info,
		},
		{
			name:       "ambient-downgrades-to-info",
			capability: CAP_CHOWN,
			risk:       LowRisk,
			capType:    "amb",
			want:       Info,
		},
		{
			name:       "inheritable-downgrades-two-levels",
			capability: CAP_SYS_RESOURCE,
			risk:       HighRisk,
			capType:    "inh",
			want:       LowRisk,
		},
		{
			name:       "bounding-downgrades-to-safe",
			capability: CAP_CHOWN,
			risk:       LowRisk,
			capType:    "bnd",
			want:       Safe,
		},
		{
			name:       "blacklisted-capability-keeps-risk-even-in-bounding",
			capability: CAP_SYS_ADMIN,
			risk:       Fatal,
			capType:    "bnd",
			want:       Fatal,
		},
		{
			name:       "unknown-cap-type-keeps-risk",
			capability: CAP_CHOWN,
			risk:       MediumRisk,
			capType:    "other",
			want:       MediumRisk,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := downgradeRiskLevel(tc.capability, tc.risk, tc.capType); got != tc.want {
				t.Fatalf("expected downgraded risk %d, got %d", tc.want, got)
			}
		})
	}
}

func TestCapabilityMountNamespaceHelpers(t *testing.T) {
	ns := target.NSRef{Type: "mnt", Dev: 44, Ino: 55}
	rule := &Rule{
		Snapshot: model.Snapshot{
			MountNamespaces: []model.NamespaceSnapshot{
				{
					NSRef: ns,
					MountInfo: []collect.MountInfo{
						{MountPoint: "/"},
						{MountPoint: "/etc"},
						{MountPoint: "/run"},
					},
				},
			},
		},
	}
	thread := &target.Thread{MntNS: ns}

	gotNS := rule.mntnsForThread(thread)
	if gotNS != &rule.Snapshot.MountNamespaces[0] {
		t.Fatalf("expected to resolve thread mount namespace to snapshot entry")
	}

	gotMountPoints := rule.mountPointsForThread(thread)
	wantMountPoints := []string{"/", "/etc", "/run"}
	if !reflect.DeepEqual(gotMountPoints, wantMountPoints) {
		t.Fatalf("expected mount points %v, got %v", wantMountPoints, gotMountPoints)
	}

	if got := mntInfo2mntPoint(rule.Snapshot.MountNamespaces[0].MountInfo); !reflect.DeepEqual(got, wantMountPoints) {
		t.Fatalf("expected mount points %v, got %v", wantMountPoints, got)
	}

	missing := &target.Thread{MntNS: target.NSRef{Type: "mnt", Dev: 99, Ino: 100}}
	if got := rule.mntnsForThread(missing); got != nil {
		t.Fatalf("expected missing mount namespace to return nil, got %#v", got)
	}
	if got := rule.mountPointsForThread(missing); got != nil {
		t.Fatalf("expected missing mount namespace to return nil mount points, got %#v", got)
	}
}

func TestAnalyzeCapabilitiesPerThreadPrioritizesAndDeduplicatesCapabilitySets(t *testing.T) {
	ns := target.NSRef{Type: "mnt", Dev: 66, Ino: 77}
	thread := &target.Thread{
		Tid:          301,
		Tgid:         300,
		Comm:         "caps-priority",
		IsMainThread: true,
		UserNS:       target.NSRef{Type: "user", Dev: 9, Ino: 10},
		MntNS:        ns,
		PIDNS:        target.NSRef{Type: "pid", Dev: 11, Ino: 12},
		CapEff:       capBit(CAP_CHOWN),
		CapPrm:       capBit(CAP_NET_BIND_SERVICE),
		CapAmb:       capBit(CAP_NET_ADMIN),
		CapInh:       capBit(CAP_SYS_RESOURCE),
		CapBnd:       capBit(CAP_CHOWN) | capBit(CAP_SYS_ADMIN),
	}
	rule := &Rule{
		Snapshot: model.Snapshot{
			MountNamespaces: []model.NamespaceSnapshot{
				{
					NSRef: ns,
					MountInfo: []collect.MountInfo{
						{MountPoint: "/"},
						{MountPoint: "/etc"},
					},
				},
			},
		},
	}

	rule.analyzeCapabilitiesPerThread(thread, len(capThreatLevels)-1)

	requireRuleSignalCount(t, rule.Signals, 5)

	chown := findSignalByTitle(rule.Signals, "Thread has CAP_CHOWN in its effective capability set")
	if chown == nil {
		t.Fatalf("expected effective CAP_CHOWN signal in %#v", rule.Signals)
	}
	if chown.RiskLevel != LowRisk {
		t.Fatalf("expected CAP_CHOWN effective risk %d, got %d", LowRisk, chown.RiskLevel)
	}

	netBind := findSignalByTitle(rule.Signals, "Thread has CAP_NET_BIND_SERVICE in its permitted capability set")
	if netBind == nil || netBind.RiskLevel != Info {
		t.Fatalf("expected permitted CAP_NET_BIND_SERVICE with risk %d, got %#v", Info, netBind)
	}

	netAdmin := findSignalByTitle(rule.Signals, "Thread has CAP_NET_ADMIN in its ambient capability set")
	if netAdmin == nil || netAdmin.RiskLevel != Fatal {
		t.Fatalf("expected ambient CAP_NET_ADMIN with fatal risk, got %#v", netAdmin)
	}

	sysResource := findSignalByTitle(rule.Signals, "Thread has CAP_SYS_RESOURCE in its inheritable capability set")
	if sysResource == nil || sysResource.RiskLevel != LowRisk {
		t.Fatalf("expected inheritable CAP_SYS_RESOURCE with low risk, got %#v", sysResource)
	}

	sysAdmin := findSignalByTitle(rule.Signals, "Thread has CAP_SYS_ADMIN in its bounding capability set")
	if sysAdmin == nil || sysAdmin.RiskLevel != Fatal {
		t.Fatalf("expected bounding CAP_SYS_ADMIN with fatal risk, got %#v", sysAdmin)
	}

	if dup := findSignalByTitle(rule.Signals, "Thread has CAP_CHOWN in its bounding capability set"); dup != nil {
		t.Fatalf("expected lower-priority CAP_CHOWN duplicate to be skipped, got %#v", dup)
	}

	for _, signal := range rule.Signals {
		if !reflect.DeepEqual(signal.MountPoint, []string{"/", "/etc"}) {
			t.Fatalf("expected mount points [\"/\" \"/etc\"], got %#v", signal.MountPoint)
		}
		if len(signal.RelativeThreads) != 1 || signal.RelativeThreads[0] != thread {
			t.Fatalf("expected original thread pointer %p, got %#v", thread, signal.RelativeThreads)
		}
	}
}

func TestAnalyzeCapabilitiesPerThreadRespectsCapLastCap(t *testing.T) {
	ns := target.NSRef{Type: "mnt", Dev: 67, Ino: 78}
	thread := &target.Thread{
		Tid:    401,
		Tgid:   400,
		Comm:   "caps-clamped",
		MntNS:  ns,
		CapEff: capBit(CAP_CHOWN) | capBit(CAP_SYS_ADMIN),
	}
	rule := &Rule{
		Snapshot: model.Snapshot{
			MountNamespaces: []model.NamespaceSnapshot{
				{
					NSRef: ns,
					MountInfo: []collect.MountInfo{
						{MountPoint: "/"},
					},
				},
			},
		},
	}

	rule.analyzeCapabilitiesPerThread(thread, CAP_CHOWN)

	requireRuleSignalCount(t, rule.Signals, 1)
	if signal := findSignalByTitle(rule.Signals, "Thread has CAP_CHOWN in its effective capability set"); signal == nil {
		t.Fatalf("expected CAP_CHOWN signal after cap_last_cap clamp, got %#v", rule.Signals)
	}
	if signal := findSignalByTitle(rule.Signals, "Thread has CAP_SYS_ADMIN in its effective capability set"); signal != nil {
		t.Fatalf("did not expect CAP_SYS_ADMIN above cap_last_cap, got %#v", signal)
	}
}

func TestAnalyzeCapabilitiesEntryPoint(t *testing.T) {
	ns := target.NSRef{Type: "mnt", Dev: 88, Ino: 99}
	rule := &Rule{
		Snapshot: model.Snapshot{
			MountNamespaces: []model.NamespaceSnapshot{
				{
					NSRef: ns,
					MountInfo: []collect.MountInfo{
						{MountPoint: "/"},
						{MountPoint: "/run"},
					},
				},
			},
			Threads: map[int]model.ThreadSnapshot{
				501: model.ThreadSnapshot(target.Thread{
					Tid:          501,
					Tgid:         500,
					Comm:         "entry-caps",
					IsMainThread: true,
					UserNS:       target.NSRef{Type: "user", Dev: 7, Ino: 8},
					MntNS:        ns,
					PIDNS:        target.NSRef{Type: "pid", Dev: 9, Ino: 10},
					CapEff:       capBit(CAP_CHOWN),
				}),
				502: model.ThreadSnapshot(target.Thread{
					Tid:   502,
					Tgid:  500,
					Comm:  "no-caps",
					MntNS: ns,
				}),
			},
		},
	}

	rule.AnalyzeCapabilities()

	requireRuleSignalCount(t, rule.Signals, 1)

	signal := findSignalByTitle(rule.Signals, "Thread has CAP_CHOWN in its effective capability set")
	if signal == nil {
		t.Fatalf("expected entrypoint to emit CAP_CHOWN signal, got %#v", rule.Signals)
	}
	if signal.Category != "capabilities" {
		t.Fatalf("expected capabilities category, got %q", signal.Category)
	}
	if signal.RiskLevel != LowRisk {
		t.Fatalf("expected CAP_CHOWN risk %d, got %d", LowRisk, signal.RiskLevel)
	}
	if !reflect.DeepEqual(signal.MountPoint, []string{"/", "/run"}) {
		t.Fatalf("expected mount points [\"/\" \"/run\"], got %#v", signal.MountPoint)
	}
	if len(signal.RelativeThreads) != 1 || signal.RelativeThreads[0] == nil {
		t.Fatalf("expected one relative thread, got %#v", signal.RelativeThreads)
	}
	if signal.RelativeThreads[0].Tid != 501 || signal.RelativeThreads[0].Tgid != 500 || signal.RelativeThreads[0].Comm != "entry-caps" {
		t.Fatalf("unexpected relative thread %#v", signal.RelativeThreads[0])
	}
}
