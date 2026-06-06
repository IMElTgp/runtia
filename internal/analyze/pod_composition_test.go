package analyze

import (
	"reflect"
	"strings"
	"testing"

	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

func podCompositionThread(tid, tgid int, pidNS, userNS target.NSRef) *target.Thread {
	return &target.Thread{
		Tid:          tid,
		Tgid:         tgid,
		Comm:         "worker",
		IsMainThread: tid == tgid,
		PIDNS:        pidNS,
		UserNS:       userNS,
	}
}

func podCompositionThreadWithMount(tid, tgid int, mntNS target.NSRef) *target.Thread {
	thread := podCompositionThread(tid, tgid, target.NSRef{Type: "pid", Dev: 99, Ino: uint64(tgid)}, target.NSRef{Type: "user", Dev: 99, Ino: uint64(tgid)})
	thread.MntNS = mntNS
	return thread
}

func podCompositionInput(container string, thread *target.Thread, findings ...*model.Finding) PodContainerAnalysis {
	snapshot := model.Snapshot{
		Metadata: model.Metadata{
			Namespace:     "default",
			PodName:       "demo",
			NodeName:      "node-a",
			ContainerName: container,
			ContainerID:   "containerd://" + container,
			Runtime:       "containerd",
			RuntimeID:     container,
			InitPID:       thread.Tgid,
		},
		PIDNamespaces:  []model.NamespaceSnapshot{{NSRef: thread.PIDNS, Owner: thread.UserNS, OwnerKnown: true}},
		UserNamespaces: []model.NamespaceSnapshot{{NSRef: thread.UserNS, Owner: thread.UserNS, OwnerKnown: true}},
		Threads: map[int]model.ThreadSnapshot{
			thread.Tid: model.ThreadSnapshot(*thread),
		},
	}
	return PodContainerAnalysis{
		Snapshot: snapshot,
		Findings: findings,
	}
}

func podCompositionMountInput(container string, thread *target.Thread, mounts []collect.MountInfo, findings ...*model.Finding) PodContainerAnalysis {
	input := podCompositionInput(container, thread, findings...)
	input.Snapshot.MountNamespaces = []model.NamespaceSnapshot{
		{
			NSRef:      thread.MntNS,
			Owner:      thread.UserNS,
			OwnerKnown: true,
			MountInfo:  mounts,
		},
	}
	input.Snapshot.Threads[thread.Tid] = model.ThreadSnapshot(*thread)
	return input
}

func podCapabilityFinding(thread *target.Thread, capName, set string) *model.Finding {
	return &model.Finding{
		Category:        "capabilities",
		RiskLevel:       HighRisk,
		Title:           "Thread has " + capName + " in its " + set + " capability set",
		Summary:         "capability finding",
		Evidence:        []string{"capability evidence"},
		RelativeThreads: []*target.Thread{thread},
	}
}

func podMount(mountID int, mountPoint, fsType, source, root string, mountOptions, superOptions []string) collect.MountInfo {
	return collect.MountInfo{
		RawLine:      mountPoint,
		MountID:      mountID,
		ParentID:     1,
		Root:         root,
		MountPoint:   mountPoint,
		MountOptions: mountOptions,
		FStype:       fsType,
		MountSource:  source,
		SuperOptions: superOptions,
	}
}

func podWritableMount(mountID int, mountPoint, fsType, source, root string) collect.MountInfo {
	return podMount(mountID, mountPoint, fsType, source, root, []string{"rw"}, []string{"rw"})
}

func podReadOnlyMount(mountID int, mountPoint, fsType, source, root string) collect.MountInfo {
	return podMount(mountID, mountPoint, fsType, source, root, []string{"ro"}, []string{"ro"})
}

func findPodCompositionByTitle(findings []*model.Finding, title string) *model.Finding {
	for _, finding := range findings {
		if finding != nil && finding.Title == title {
			return finding
		}
	}
	return nil
}

func findAllPodCompositionByTitle(findings []*model.Finding, title string) []*model.Finding {
	var got []*model.Finding
	for _, finding := range findings {
		if finding != nil && finding.Title == title {
			got = append(got, finding)
		}
	}
	return got
}

func TestComposePodFindingsSharedPIDNamespaceWithProcessControlCapability(t *testing.T) {
	pidNS := target.NSRef{Type: "pid", Dev: 1, Ino: 200}
	userNS := target.NSRef{Type: "user", Dev: 1, Ino: 100}
	tracer := podCompositionThread(1001, 1001, pidNS, userNS)
	targetThread := podCompositionThread(2001, 2001, pidNS, userNS)

	got := ComposePodFindings([]PodContainerAnalysis{
		podCompositionInput("debugger", tracer, podCapabilityFinding(tracer, "CAP_SYS_PTRACE", "effective")),
		podCompositionInput("app", targetThread),
	})

	finding := findPodCompositionByTitle(got, "Shared PID namespace with process-control capability")
	if finding == nil {
		t.Fatalf("expected shared PIDNS process-control composition, got %#v", got)
	}
	if finding.Category != "composition" || finding.RiskLevel != HighRisk {
		t.Fatalf("unexpected composition finding %#v", finding)
	}
	if len(finding.Containers) != 2 {
		t.Fatalf("expected both containers in finding context, got %#v", finding.Containers)
	}
	joinedEvidence := strings.Join(finding.Evidence, "\n")
	for _, want := range []string{"CAP_SYS_PTRACE", "shared PID namespace", "debugger", "app", "user namespace"} {
		if !strings.Contains(joinedEvidence, want) {
			t.Fatalf("expected evidence to contain %q, got %q", want, joinedEvidence)
		}
	}
}

func TestComposePodFindingsSharedPIDNamespaceWithCAPKill(t *testing.T) {
	pidNS := target.NSRef{Type: "pid", Dev: 1, Ino: 201}
	userNS := target.NSRef{Type: "user", Dev: 1, Ino: 101}
	killer := podCompositionThread(1101, 1101, pidNS, userNS)
	targetThread := podCompositionThread(2101, 2101, pidNS, userNS)

	got := ComposePodFindings([]PodContainerAnalysis{
		podCompositionInput("killer", killer, podCapabilityFinding(killer, "CAP_KILL", "permitted")),
		podCompositionInput("app", targetThread),
	})

	if finding := findPodCompositionByTitle(got, "Shared PID namespace with process-control capability"); finding == nil {
		t.Fatalf("expected CAP_KILL shared PIDNS composition, got %#v", got)
	}
}

func TestComposePodFindingsDoesNotComposeSameContainerProcessControl(t *testing.T) {
	pidNS := target.NSRef{Type: "pid", Dev: 1, Ino: 202}
	userNS := target.NSRef{Type: "user", Dev: 1, Ino: 102}
	thread := podCompositionThread(1201, 1201, pidNS, userNS)

	got := ComposePodFindings([]PodContainerAnalysis{
		podCompositionInput("only", thread, podCapabilityFinding(thread, "CAP_SYS_PTRACE", "effective")),
	})

	if finding := findPodCompositionByTitle(got, "Shared PID namespace with process-control capability"); finding != nil {
		t.Fatalf("did not expect same-container composition, got %#v", finding)
	}
}

func TestComposePodFindingsDoesNotComposeDifferentPIDNamespaces(t *testing.T) {
	userNS := target.NSRef{Type: "user", Dev: 1, Ino: 103}
	tracer := podCompositionThread(1301, 1301, target.NSRef{Type: "pid", Dev: 1, Ino: 203}, userNS)
	targetThread := podCompositionThread(2301, 2301, target.NSRef{Type: "pid", Dev: 1, Ino: 204}, userNS)

	got := ComposePodFindings([]PodContainerAnalysis{
		podCompositionInput("debugger", tracer, podCapabilityFinding(tracer, "CAP_SYS_PTRACE", "effective")),
		podCompositionInput("app", targetThread),
	})

	if finding := findPodCompositionByTitle(got, "Shared PID namespace with process-control capability"); finding != nil {
		t.Fatalf("did not expect composition across different PID namespaces, got %#v", finding)
	}
}

func TestComposePodFindingsSharedPIDNamespaceDACRequiresSameUserNamespace(t *testing.T) {
	pidNS := target.NSRef{Type: "pid", Dev: 1, Ino: 205}
	sourceUserNS := target.NSRef{Type: "user", Dev: 1, Ino: 105}
	targetUserNS := target.NSRef{Type: "user", Dev: 1, Ino: 106}
	reader := podCompositionThread(1401, 1401, pidNS, sourceUserNS)
	targetThread := podCompositionThread(2401, 2401, pidNS, targetUserNS)

	got := ComposePodFindings([]PodContainerAnalysis{
		podCompositionInput("reader", reader, podCapabilityFinding(reader, "CAP_DAC_READ_SEARCH", "effective")),
		podCompositionInput("app", targetThread),
	})

	if finding := findPodCompositionByTitle(got, "Shared PID namespace with proc-root DAC exposure"); finding != nil {
		t.Fatalf("did not expect DAC proc-root composition across different user namespaces, got %#v", finding)
	}

	targetThread.UserNS = sourceUserNS
	got = ComposePodFindings([]PodContainerAnalysis{
		podCompositionInput("reader", reader, podCapabilityFinding(reader, "CAP_DAC_READ_SEARCH", "effective")),
		podCompositionInput("app", targetThread),
	})

	finding := findPodCompositionByTitle(got, "Shared PID namespace with proc-root DAC exposure")
	if finding == nil {
		t.Fatalf("expected DAC proc-root composition for same user namespace, got %#v", got)
	}
	if finding.RiskLevel != HighRisk {
		t.Fatalf("expected HighRisk DAC composition, got %#v", finding)
	}
}

func TestComposePodFindingsIgnoresSeccompCapabilityAcrossContainers(t *testing.T) {
	pidNS := target.NSRef{Type: "pid", Dev: 1, Ino: 206}
	userNS := target.NSRef{Type: "user", Dev: 1, Ino: 107}
	source := podCompositionThread(1501, 1501, pidNS, userNS)
	targetThread := podCompositionThread(2501, 2501, pidNS, userNS)
	seccompFinding := &model.Finding{
		Category:        "seccomp",
		RiskLevel:       HighRisk,
		Title:           "Thread runs without seccomp filtering",
		RelativeThreads: []*target.Thread{targetThread},
	}

	got := ComposePodFindings([]PodContainerAnalysis{
		podCompositionInput("nettool", source, podCapabilityFinding(source, "CAP_NET_RAW", "effective")),
		podCompositionInput("app", targetThread, seccompFinding),
	})

	for _, finding := range got {
		if finding != nil && strings.Contains(finding.Title, "seccomp") {
			t.Fatalf("did not expect seccomp-based cross-container composition, got %#v", finding)
		}
	}
}

func TestComposePodFindingsUsesCoveredCapabilitySignalsForPodComposition(t *testing.T) {
	pidNS := target.NSRef{Type: "pid", Dev: 1, Ino: 207}
	userNS := target.NSRef{Type: "user", Dev: 1, Ino: 108}
	tracer := podCompositionThread(1601, 1601, pidNS, userNS)
	targetThread := podCompositionThread(2601, 2601, pidNS, userNS)
	capability := podCapabilityFinding(tracer, "CAP_SYS_PTRACE", "effective")

	got := ComposePodFindings([]PodContainerAnalysis{
		{
			Snapshot: podCompositionInput("debugger", tracer).Snapshot,
			Signals: []model.Signal{
				{
					Finding: *capability,
					Covered: true,
				},
			},
			Findings: nil,
		},
		podCompositionInput("app", targetThread),
	})

	if finding := findPodCompositionByTitle(got, "Shared PID namespace with process-control capability"); finding == nil {
		t.Fatalf("expected covered primitive capability signal to remain available for pod composition, got %#v", got)
	}
}

func TestComposePodFindingsSharedVolumeWritableProducerSensitiveConsumer(t *testing.T) {
	producerNS := target.NSRef{Type: "mnt", Dev: 2, Ino: 300}
	consumerNS := target.NSRef{Type: "mnt", Dev: 2, Ino: 301}
	producer := podCompositionThreadWithMount(3001, 3001, producerNS)
	consumer := podCompositionThreadWithMount(4001, 4001, consumerNS)

	got := ComposePodFindings([]PodContainerAnalysis{
		podCompositionMountInput(
			"writer",
			producer,
			[]collect.MountInfo{
				podWritableMount(1, "/writer", "ext4", "/dev/disk/by-id/pod-volume", "/pod-volume"),
				podWritableMount(2, "/writer-alt", "ext4", "/dev/disk/by-id/pod-volume", "/pod-volume"),
			},
			podCapabilityFinding(producer, "CAP_CHOWN", "effective"),
			podCapabilityFinding(producer, "CAP_SETFCAP", "permitted"),
		),
		podCompositionMountInput(
			"consumer",
			consumer,
			[]collect.MountInfo{
				podReadOnlyMount(3, "/etc/config", "ext4", "/dev/disk/by-id/pod-volume", "/pod-volume"),
				podReadOnlyMount(4, "/etc/ssl", "ext4", "/dev/disk/by-id/pod-volume", "/pod-volume"),
			},
		),
	})

	findings := findAllPodCompositionByTitle(got, "Shared volume writable producer can affect sensitive consumer path")
	if len(findings) != 1 {
		t.Fatalf("expected one merged shared-volume finding, got %#v", got)
	}
	finding := findings[0]
	if finding.Category != "composition" || finding.RiskLevel != HighRisk {
		t.Fatalf("unexpected shared-volume finding %#v", finding)
	}
	if len(finding.Containers) != 2 || finding.Containers[0].Name != "writer" || finding.Containers[1].Name != "consumer" {
		t.Fatalf("expected directional producer/consumer containers, got %#v", finding.Containers)
	}
	wantMountPoints := []string{"/writer", "/writer-alt", "/etc/config", "/etc/ssl"}
	if !reflect.DeepEqual(finding.MountPoint, wantMountPoints) {
		t.Fatalf("expected producer mount points followed by consumer mount points %v, got %#v", wantMountPoints, finding.MountPoint)
	}
	if finding.RelativeNS == nil || *finding.RelativeNS != producerNS {
		t.Fatalf("expected producer mount namespace as RelativeNS, got %#v", finding.RelativeNS)
	}
	if !reflect.DeepEqual(finding.RelativeNSs, []target.NSRef{producerNS, consumerNS}) {
		t.Fatalf("expected RelativeNSs producer then consumer, got %#v", finding.RelativeNSs)
	}
	if len(finding.RelativeThreads) != 2 || finding.RelativeThreads[0].Tid != producer.Tid || finding.RelativeThreads[1].Tid != consumer.Tid {
		t.Fatalf("expected producer and consumer representative threads, got %#v", finding.RelativeThreads)
	}
	joinedEvidence := strings.Join(finding.Evidence, "\n")
	for _, want := range []string{
		"backing source",
		"fstype=ext4",
		"source=/dev/disk/by-id/pod-volume",
		"root=/pod-volume",
		"producer writable mount points=/writer, /writer-alt",
		"consumer sensitive mount points=/etc/config, /etc/ssl",
		"CAP_CHOWN",
		"CAP_SETFCAP",
	} {
		if !strings.Contains(joinedEvidence, want) {
			t.Fatalf("expected evidence to contain %q, got %q", want, joinedEvidence)
		}
	}
	if !strings.Contains(finding.Summary, "capability amplifiers") || !strings.Contains(finding.Summary, "CAP_CHOWN") {
		t.Fatalf("expected summary to include capability amplifiers, got %q", finding.Summary)
	}
	if !strings.Contains(finding.Recommendation, "Do not mount the same backing source writable") {
		t.Fatalf("unexpected recommendation %q", finding.Recommendation)
	}
}

func TestComposePodFindingsSharedVolumeRelativeNSMatchesProducerRepresentativeThread(t *testing.T) {
	producerMainNS := target.NSRef{Type: "mnt", Dev: 2, Ino: 360}
	producerWriterNS := target.NSRef{Type: "mnt", Dev: 2, Ino: 361}
	consumerNS := target.NSRef{Type: "mnt", Dev: 2, Ino: 362}
	producerMain := podCompositionThreadWithMount(3601, 3601, producerMainNS)
	producerWorker := podCompositionThreadWithMount(3602, 3601, producerWriterNS)
	consumer := podCompositionThreadWithMount(4601, 4601, consumerNS)

	producerInput := podCompositionMountInput("writer", producerMain, []collect.MountInfo{})
	producerInput.Snapshot.MountNamespaces = []model.NamespaceSnapshot{
		{
			NSRef:      producerWriterNS,
			Owner:      producerWorker.UserNS,
			OwnerKnown: true,
			MountInfo: []collect.MountInfo{
				podWritableMount(1, "/writer", "ext4", "/dev/sde1", "/shared"),
			},
		},
	}
	producerInput.Snapshot.Threads[producerWorker.Tid] = model.ThreadSnapshot(*producerWorker)

	got := ComposePodFindings([]PodContainerAnalysis{
		producerInput,
		podCompositionMountInput("consumer", consumer, []collect.MountInfo{
			podReadOnlyMount(2, "/etc/config", "ext4", "/dev/sde1", "/shared"),
		}),
	})

	findings := findAllPodCompositionByTitle(got, "Shared volume writable producer can affect sensitive consumer path")
	if len(findings) != 1 {
		t.Fatalf("expected one shared-volume finding, got %#v", got)
	}
	finding := findings[0]
	if finding.RelativeNS == nil || *finding.RelativeNS != producerWriterNS {
		t.Fatalf("expected RelativeNS to match producer writable mount namespace, got %#v", finding.RelativeNS)
	}
	if len(finding.RelativeThreads) == 0 || finding.RelativeThreads[0].Tid != producerWorker.Tid || finding.RelativeThreads[0].MntNS != producerWriterNS {
		t.Fatalf("expected producer representative thread from writable mount namespace, got %#v", finding.RelativeThreads)
	}
}

func TestComposePodFindingsSharedVolumeUsesCoveredCapabilitySignalsAsAmplifiers(t *testing.T) {
	producerNS := target.NSRef{Type: "mnt", Dev: 2, Ino: 370}
	consumerNS := target.NSRef{Type: "mnt", Dev: 2, Ino: 371}
	producer := podCompositionThreadWithMount(3701, 3701, producerNS)
	consumer := podCompositionThreadWithMount(4701, 4701, consumerNS)
	capability := podCapabilityFinding(producer, "CAP_FOWNER", "permitted")

	got := ComposePodFindings([]PodContainerAnalysis{
		{
			Snapshot: podCompositionMountInput("writer", producer, []collect.MountInfo{
				podWritableMount(1, "/writer", "ext4", "/dev/sdf1", "/shared"),
			}).Snapshot,
			Signals: []model.Signal{{Finding: *capability, Covered: true}},
		},
		podCompositionMountInput("consumer", consumer, []collect.MountInfo{
			podReadOnlyMount(2, "/etc/config", "ext4", "/dev/sdf1", "/shared"),
		}),
	})

	findings := findAllPodCompositionByTitle(got, "Shared volume writable producer can affect sensitive consumer path")
	if len(findings) != 1 {
		t.Fatalf("expected one shared-volume finding, got %#v", got)
	}
	if !strings.Contains(strings.Join(findings[0].Evidence, "\n"), "CAP_FOWNER") {
		t.Fatalf("expected covered capability signal to appear as amplifier evidence, got %#v", findings[0].Evidence)
	}
}

func TestComposePodFindingsSharedVolumeDoesNotTriggerForNonSensitiveConsumerPath(t *testing.T) {
	producer := podCompositionThreadWithMount(3101, 3101, target.NSRef{Type: "mnt", Dev: 2, Ino: 310})
	consumer := podCompositionThreadWithMount(4101, 4101, target.NSRef{Type: "mnt", Dev: 2, Ino: 311})

	got := ComposePodFindings([]PodContainerAnalysis{
		podCompositionMountInput("writer", producer, []collect.MountInfo{
			podWritableMount(1, "/writer", "ext4", "/dev/sdb1", "/shared"),
		}),
		podCompositionMountInput("reader", consumer, []collect.MountInfo{
			podReadOnlyMount(2, "/data", "ext4", "/dev/sdb1", "/shared"),
		}),
	})

	if findings := findAllPodCompositionByTitle(got, "Shared volume writable producer can affect sensitive consumer path"); len(findings) != 0 {
		t.Fatalf("did not expect ordinary shared data path to trigger, got %#v", findings)
	}
}

func TestComposePodFindingsSharedVolumeRequiresExactBackingSourceKey(t *testing.T) {
	producer := podCompositionThreadWithMount(3201, 3201, target.NSRef{Type: "mnt", Dev: 2, Ino: 320})
	consumer := podCompositionThreadWithMount(4201, 4201, target.NSRef{Type: "mnt", Dev: 2, Ino: 321})

	got := ComposePodFindings([]PodContainerAnalysis{
		podCompositionMountInput("writer", producer, []collect.MountInfo{
			podWritableMount(1, "/writer", "ext4", "/dev/sdb1", "/shared"),
		}),
		podCompositionMountInput("consumer", consumer, []collect.MountInfo{
			podReadOnlyMount(2, "/etc/config", "ext4", "/dev/sdb1", "/shared/config"),
		}),
	})

	if findings := findAllPodCompositionByTitle(got, "Shared volume writable producer can affect sensitive consumer path"); len(findings) != 0 {
		t.Fatalf("did not expect root parent-child overlap to trigger in MVP, got %#v", findings)
	}
}

func TestComposePodFindingsSharedVolumeSkipsExcludedAndIncompleteBackingSources(t *testing.T) {
	producer := podCompositionThreadWithMount(3301, 3301, target.NSRef{Type: "mnt", Dev: 2, Ino: 330})
	consumer := podCompositionThreadWithMount(4301, 4301, target.NSRef{Type: "mnt", Dev: 2, Ino: 331})

	got := ComposePodFindings([]PodContainerAnalysis{
		podCompositionMountInput("writer", producer, []collect.MountInfo{
			podWritableMount(1, "/writer-overlay", "overlay.work", "overlay", "/"),
			podWritableMount(2, "/writer-empty-source", "ext4", "", "/shared"),
		}),
		podCompositionMountInput("consumer", consumer, []collect.MountInfo{
			podReadOnlyMount(3, "/etc/overlay", "overlay.work", "overlay", "/"),
			podReadOnlyMount(4, "/etc/empty-source", "ext4", "", "/shared"),
		}),
	})

	if findings := findAllPodCompositionByTitle(got, "Shared volume writable producer can affect sensitive consumer path"); len(findings) != 0 {
		t.Fatalf("did not expect excluded or incomplete backing sources to trigger, got %#v", findings)
	}
}

func TestComposePodFindingsSharedVolumeRequiresProducerWritableButIgnoresConsumerReadWrite(t *testing.T) {
	producer := podCompositionThreadWithMount(3401, 3401, target.NSRef{Type: "mnt", Dev: 2, Ino: 340})
	consumer := podCompositionThreadWithMount(4401, 4401, target.NSRef{Type: "mnt", Dev: 2, Ino: 341})

	got := ComposePodFindings([]PodContainerAnalysis{
		podCompositionMountInput("writer", producer, []collect.MountInfo{
			podWritableMount(1, "/writer", "ext4", "/dev/sdc1", "/shared"),
		}),
		podCompositionMountInput("consumer", consumer, []collect.MountInfo{
			podWritableMount(2, "/etc/config", "ext4", "/dev/sdc1", "/shared"),
		}),
	})
	if findings := findAllPodCompositionByTitle(got, "Shared volume writable producer can affect sensitive consumer path"); len(findings) != 1 {
		t.Fatalf("expected consumer rw state not to suppress shared-volume finding, got %#v", got)
	}
	if got[0].Containers[0].Name != "writer" || got[0].Containers[1].Name != "consumer" {
		t.Fatalf("expected writable producer to remain producer and rw sensitive mount to remain consumer, got %#v", got[0].Containers)
	}
}

func TestComposePodFindingsSharedVolumeEmitsTwoDirectionalFindings(t *testing.T) {
	first := podCompositionThreadWithMount(3501, 3501, target.NSRef{Type: "mnt", Dev: 2, Ino: 350})
	second := podCompositionThreadWithMount(4501, 4501, target.NSRef{Type: "mnt", Dev: 2, Ino: 351})

	got := ComposePodFindings([]PodContainerAnalysis{
		podCompositionMountInput("first", first, []collect.MountInfo{
			podWritableMount(1, "/writer", "ext4", "/dev/sdd1", "/shared"),
			podReadOnlyMount(2, "/etc/first", "ext4", "/dev/sdd1", "/shared"),
		}),
		podCompositionMountInput("second", second, []collect.MountInfo{
			podWritableMount(3, "/writer", "ext4", "/dev/sdd1", "/shared"),
			podReadOnlyMount(4, "/etc/second", "ext4", "/dev/sdd1", "/shared"),
		}),
	})

	findings := findAllPodCompositionByTitle(got, "Shared volume writable producer can affect sensitive consumer path")
	if len(findings) != 2 {
		t.Fatalf("expected two directional findings, got %#v", findings)
	}
	if findings[0].Containers[0].Name == findings[1].Containers[0].Name {
		t.Fatalf("expected opposite producer directions, got %#v", findings)
	}
}
