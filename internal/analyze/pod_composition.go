package analyze

import (
	"fmt"
	"slices"
	"strings"

	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

type PodContainerAnalysis struct {
	Snapshot model.Snapshot
	Signals  []model.Signal
	Findings []*model.Finding
}

type podContainerFacts struct {
	input   PodContainerAnalysis
	key     string
	context model.ContainerContext
	threads []target.Thread
	mounts  []containerMountFact
}

type backingSourceKey struct {
	FSType string
	Source string
	Root   string
}

type containerMountFact struct {
	info       collect.MountInfo
	namespace  target.NSRef
	sourceKey  backingSourceKey
	writable   bool
	sensitive  bool
	vitalPath  string
	mountPoint string
}

func ComposePodFindings(inputs []PodContainerAnalysis) []*model.Finding {
	facts := make([]podContainerFacts, 0, len(inputs))
	for _, input := range inputs {
		fact := podContainerFacts{
			input:   input,
			key:     containerAnalysisKey(input.Snapshot),
			context: model.ContainerContextFromSnapshot(input.Snapshot),
			threads: snapshotThreads(input.Snapshot),
		}
		fact.mounts = snapshotMountFacts(input.Snapshot)
		if fact.key == "" || len(fact.threads) == 0 {
			continue
		}
		facts = append(facts, fact)
	}

	composer := podComposer{
		facts: facts,
		seen:  make(map[string]struct{}),
	}
	composer.composeSharedPIDProcessControl()
	composer.composeSharedPIDProcRootDAC()
	composer.composeSharedVolumeWritableProducerSensitiveConsumer()
	return composer.findings
}

type podComposer struct {
	facts    []podContainerFacts
	seen     map[string]struct{}
	findings []*model.Finding
}

func (c *podComposer) composeSharedPIDProcessControl() {
	for sourceIdx := range c.facts {
		source := c.facts[sourceIdx]
		for _, capability := range capabilityFindings(source.input) {
			capName, ok := processControlCapability(capability)
			if !ok {
				continue
			}
			sourceThread := firstFindingThread(capability)
			if sourceThread == nil || isZeroNamespace(sourceThread.PIDNS) {
				continue
			}

			for targetIdx := range c.facts {
				targetFact := c.facts[targetIdx]
				if source.key == targetFact.key {
					continue
				}
				targetThread, ok := firstThreadInPIDNamespace(targetFact.threads, sourceThread.PIDNS)
				if !ok {
					continue
				}

				c.appendDeduped(
					fmt.Sprintf("pid-process-control|%s|%s|%s|%s", source.key, targetFact.key, capName, formatNSRef(sourceThread.PIDNS)),
					newPodCompositionFinding(
						HighRisk,
						"Shared PID namespace with process-control capability",
						fmt.Sprintf("Container %s has %s while container %s has visible processes in the same PID namespace.", source.context.Name, capName, targetFact.context.Name),
						"Avoid sharing a PID namespace with containers that retain process-control capabilities. Drop CAP_SYS_PTRACE and CAP_KILL unless they are explicitly required.",
						source.input.Snapshot,
						[]model.ContainerContext{source.context, targetFact.context},
						[]*target.Thread{sourceThread, &targetThread},
						sourceThread.PIDNS,
						[]string{
							fmt.Sprintf("source container=%s has %s in %s set", readableContainerName(source.context), capName, capabilitySetLabelFromFinding(capability)),
							fmt.Sprintf("target container=%s has process tid=%d in shared PID namespace %s", readableContainerName(targetFact.context), targetThread.Tid, formatNSRef(targetThread.PIDNS)),
							fmt.Sprintf("capability thread user namespace=%s", formatNSRef(sourceThread.UserNS)),
						},
					),
				)
			}
		}
	}
}

func (c *podComposer) composeSharedPIDProcRootDAC() {
	for sourceIdx := range c.facts {
		source := c.facts[sourceIdx]
		for _, capability := range capabilityFindings(source.input) {
			capName, ok := dacCapability(capability)
			if !ok {
				continue
			}
			sourceThread := firstFindingThread(capability)
			if sourceThread == nil || isZeroNamespace(sourceThread.PIDNS) || isZeroNamespace(sourceThread.UserNS) {
				continue
			}

			for targetIdx := range c.facts {
				targetFact := c.facts[targetIdx]
				if source.key == targetFact.key {
					continue
				}
				targetThread, ok := firstThreadInPIDAndUserNamespace(targetFact.threads, sourceThread.PIDNS, sourceThread.UserNS)
				if !ok {
					continue
				}

				c.appendDeduped(
					fmt.Sprintf("pid-proc-root-dac|%s|%s|%s|%s|%s", source.key, targetFact.key, capName, formatNSRef(sourceThread.PIDNS), formatNSRef(sourceThread.UserNS)),
					newPodCompositionFinding(
						HighRisk,
						"Shared PID namespace with proc-root DAC exposure",
						fmt.Sprintf("Container %s has %s while container %s has visible processes in the same PID and user namespace, making /proc/$pid/root exposure more sensitive.", source.context.Name, capName, targetFact.context.Name),
						"Do not combine shared PID namespaces with DAC-bypass capabilities. Keep containers in separate PID namespaces or drop CAP_DAC_READ_SEARCH and CAP_DAC_OVERRIDE.",
						source.input.Snapshot,
						[]model.ContainerContext{source.context, targetFact.context},
						[]*target.Thread{sourceThread, &targetThread},
						sourceThread.PIDNS,
						[]string{
							fmt.Sprintf("source container=%s has %s in %s set", readableContainerName(source.context), capName, capabilitySetLabelFromFinding(capability)),
							fmt.Sprintf("target container=%s has process tid=%d reachable through shared PID namespace %s", readableContainerName(targetFact.context), targetThread.Tid, formatNSRef(targetThread.PIDNS)),
							fmt.Sprintf("MVP user namespace compatibility: both threads use user namespace %s", formatNSRef(sourceThread.UserNS)),
							"/proc/$pid/root may expose the target container filesystem view when processes are visible in the shared PID namespace",
						},
					),
				)
			}
		}
	}
}

func (c *podComposer) composeSharedVolumeWritableProducerSensitiveConsumer() {
	for producerIdx := range c.facts {
		producer := c.facts[producerIdx]
		producerBySource := writableMountsBySource(producer.mounts)
		if len(producerBySource) == 0 {
			continue
		}

		amplifiers := producerCapabilityAmplifiers(producer.input)
		for consumerIdx := range c.facts {
			consumer := c.facts[consumerIdx]
			if producer.key == consumer.key {
				continue
			}
			consumerBySource := sensitiveMountsBySource(consumer.mounts)
			if len(consumerBySource) == 0 {
				continue
			}

			for sourceKey, producerMounts := range producerBySource {
				consumerMounts := consumerBySource[sourceKey]
				if len(consumerMounts) == 0 {
					continue
				}

				relativeNSs := relatedMountNamespaces(producerMounts, consumerMounts)
				relativeNS := target.NSRef{}
				relativeThreads := representativeThreadsForMounts(producer, consumer, producerMounts, consumerMounts)
				if len(relativeThreads) > 0 && relativeThreads[0] != nil && !isZeroNamespace(relativeThreads[0].MntNS) {
					relativeNS = relativeThreads[0].MntNS
				} else if len(relativeNSs) > 0 {
					relativeNS = relativeNSs[0]
				}
				producerMountPoints := uniqueMountPoints(producerMounts)
				consumerMountPoints := uniqueMountPoints(consumerMounts)
				// MountPoint ordering is directional: producer writable mount points first,
				// then consumer sensitive mount points.
				mountPoints := append(append([]string{}, producerMountPoints...), consumerMountPoints...)

				c.appendDeduped(
					fmt.Sprintf("shared-volume|%s|%s|%s|%s|%s", producer.key, consumer.key, sourceKey.FSType, sourceKey.Source, sourceKey.Root),
					newPodCompositionFindingWithNamespaces(
						HighRisk,
						"Shared volume writable producer can affect sensitive consumer path",
						sharedVolumeSummary(producer.context, consumer.context, consumerMountPoints, amplifiers),
						"Do not mount the same backing source writable in one container and at sensitive paths in another container. Split the volume, make the producer mount read-only where possible, or move the consumer mount away from sensitive runtime/host paths. Drop producer capability amplifiers unless they are explicitly required.",
						producer.input.Snapshot,
						[]model.ContainerContext{producer.context, consumer.context},
						relativeThreads,
						relativeNS,
						relativeNSs,
						mountPoints,
						sharedVolumeEvidence(producer, consumer, sourceKey, producerMounts, consumerMounts, amplifiers, relativeThreads),
					),
				)
			}
		}
	}
}

func (c *podComposer) appendDeduped(key string, finding *model.Finding) {
	if finding == nil {
		return
	}
	if _, ok := c.seen[key]; ok {
		return
	}
	c.seen[key] = struct{}{}
	c.findings = append(c.findings, finding)
}

func newPodCompositionFinding(
	risk int,
	title, summary, recommendation string,
	source model.Snapshot,
	containers []model.ContainerContext,
	threads []*target.Thread,
	relativeNS target.NSRef,
	evidence []string,
) *model.Finding {
	return newPodCompositionFindingWithNamespaces(risk, title, summary, recommendation, source, containers, threads, relativeNS, nil, nil, evidence)
}

func newPodCompositionFindingWithNamespaces(
	risk int,
	title, summary, recommendation string,
	source model.Snapshot,
	containers []model.ContainerContext,
	threads []*target.Thread,
	relativeNS target.NSRef,
	relativeNSs []target.NSRef,
	mountPoints []string,
	evidence []string,
) *model.Finding {
	ns := relativeNS
	finding := &model.Finding{
		Category:        "composition",
		RiskLevel:       risk,
		Title:           title,
		Summary:         summary,
		Evidence:        evidence,
		Namespace:       source.Namespace,
		PodName:         source.PodName,
		NodeName:        source.NodeName,
		Containers:      containers,
		RelativeThreads: threads,
		RelativeNSs:     relativeNSs,
		MountPoint:      mountPoints,
		Recommendation:  recommendation,
	}
	if !isZeroNamespace(ns) {
		finding.RelativeNS = &ns
	}
	return finding
}

func processControlCapability(finding *model.Finding) (string, bool) {
	return selectedCapability(finding, []string{"CAP_SYS_PTRACE", "CAP_KILL"})
}

func dacCapability(finding *model.Finding) (string, bool) {
	return selectedCapability(finding, []string{"CAP_DAC_READ_SEARCH", "CAP_DAC_OVERRIDE"})
}

func volumeCapabilityAmplifier(finding *model.Finding) (string, bool) {
	return selectedCapability(finding, []string{"CAP_CHOWN", "CAP_FOWNER", "CAP_DAC_OVERRIDE", "CAP_SETFCAP"})
}

func selectedCapability(finding *model.Finding, names []string) (string, bool) {
	if finding == nil || finding.Category != "capabilities" {
		return "", false
	}
	set := capabilitySetLabelFromFinding(finding)
	if set != "effective" && set != "permitted" {
		return "", false
	}
	name := ParseCapabilityNameFromFinding(finding)
	for _, candidate := range names {
		if name == candidate {
			return name, true
		}
	}
	return "", false
}

func firstFindingThread(finding *model.Finding) *target.Thread {
	if finding == nil {
		return nil
	}
	for _, thread := range finding.RelativeThreads {
		if thread != nil {
			return thread
		}
	}
	return nil
}

func firstThreadInPIDNamespace(threads []target.Thread, pidNS target.NSRef) (target.Thread, bool) {
	for _, thread := range threads {
		if !isZeroNamespace(thread.PIDNS) && thread.PIDNS == pidNS {
			return thread, true
		}
	}
	return target.Thread{}, false
}

func firstThreadInPIDAndUserNamespace(threads []target.Thread, pidNS, userNS target.NSRef) (target.Thread, bool) {
	for _, thread := range threads {
		if !isZeroNamespace(thread.PIDNS) && !isZeroNamespace(thread.UserNS) && thread.PIDNS == pidNS && thread.UserNS == userNS {
			return thread, true
		}
	}
	return target.Thread{}, false
}

func snapshotThreads(snapshot model.Snapshot) []target.Thread {
	threads := make([]target.Thread, 0, len(snapshot.Threads))
	for _, thread := range snapshot.Threads {
		threads = append(threads, target.Thread(thread))
	}
	return threads
}

func snapshotMountFacts(snapshot model.Snapshot) []containerMountFact {
	facts := make([]containerMountFact, 0)
	for _, namespace := range snapshot.MountNamespaces {
		for _, info := range namespace.MountInfo {
			sourceKey, ok := mountBackingSourceKey(info)
			if !ok {
				continue
			}
			sensitive, vitalPath := isSensitiveConsumerMount(info)
			facts = append(facts, containerMountFact{
				info:       info,
				namespace:  namespace.NSRef,
				sourceKey:  sourceKey,
				writable:   isMountWritable(&info),
				sensitive:  sensitive,
				vitalPath:  vitalPath,
				mountPoint: info.MountPoint,
			})
		}
	}
	return facts
}

func mountBackingSourceKey(info collect.MountInfo) (backingSourceKey, bool) {
	fsType := fsMainType(info.FStype)
	source := strings.TrimSpace(info.MountSource)
	root := strings.TrimSpace(info.Root)
	if fsType == "" || source == "" || root == "" {
		return backingSourceKey{}, false
	}
	if excludedBackingSourceFSType(fsType) {
		return backingSourceKey{}, false
	}
	return backingSourceKey{FSType: fsType, Source: source, Root: root}, true
}

func fsMainType(fsType string) string {
	fsType = strings.TrimSpace(fsType)
	if fsType == "" {
		return ""
	}
	mainType, _, _ := strings.Cut(fsType, ".")
	return mainType
}

func excludedBackingSourceFSType(fsType string) bool {
	switch fsType {
	case "proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue", "securityfs", "debugfs", "tracefs", "configfs", "fusectl", "tmpfs", "devtmpfs", "overlay":
		return true
	default:
		return false
	}
}

func isSensitiveConsumerMount(info collect.MountInfo) (bool, string) {
	for _, vitalPath := range []string{"/proc/sys", "/sys", "/sys/fs", "/host", "/rootfs", "/etc", "/run", "/var/run", "/dev"} {
		if !pathIsSameOrChild(info.MountPoint, vitalPath) {
			continue
		}
		if strings.HasPrefix(fsMainType(info.FStype), "tmpfs") {
			switch vitalPath {
			case "/dev", "/run", "/var/run":
				return false, ""
			}
		}
		return true, vitalPath
	}
	return false, ""
}

func pathIsSameOrChild(path, parent string) bool {
	path = strings.TrimRight(strings.TrimSpace(path), "/")
	parent = strings.TrimRight(strings.TrimSpace(parent), "/")
	if path == "" {
		path = "/"
	}
	if parent == "" {
		parent = "/"
	}
	if path == parent {
		return true
	}
	if parent == "/" {
		return strings.HasPrefix(path, "/")
	}
	return strings.HasPrefix(path, parent+"/")
}

func writableMountsBySource(mounts []containerMountFact) map[backingSourceKey][]containerMountFact {
	result := make(map[backingSourceKey][]containerMountFact)
	for _, mount := range mounts {
		if mount.writable {
			result[mount.sourceKey] = append(result[mount.sourceKey], mount)
		}
	}
	return result
}

func sensitiveMountsBySource(mounts []containerMountFact) map[backingSourceKey][]containerMountFact {
	result := make(map[backingSourceKey][]containerMountFact)
	for _, mount := range mounts {
		if mount.sensitive {
			result[mount.sourceKey] = append(result[mount.sourceKey], mount)
		}
	}
	return result
}

func uniqueMountPoints(mounts []containerMountFact) []string {
	points := make([]string, 0, len(mounts))
	seen := make(map[string]struct{}, len(mounts))
	for _, mount := range mounts {
		if mount.mountPoint == "" {
			continue
		}
		if _, ok := seen[mount.mountPoint]; ok {
			continue
		}
		seen[mount.mountPoint] = struct{}{}
		points = append(points, mount.mountPoint)
	}
	return points
}

func relatedMountNamespaces(producerMounts, consumerMounts []containerMountFact) []target.NSRef {
	refs := make([]target.NSRef, 0, len(producerMounts)+len(consumerMounts))
	seen := make(map[target.NSRef]struct{})
	for _, mount := range append(append([]containerMountFact{}, producerMounts...), consumerMounts...) {
		if isZeroNamespace(mount.namespace) {
			continue
		}
		if _, ok := seen[mount.namespace]; ok {
			continue
		}
		seen[mount.namespace] = struct{}{}
		refs = append(refs, mount.namespace)
	}
	return refs
}

func representativeThreads(producer, consumer podContainerFacts) []*target.Thread {
	threads := make([]*target.Thread, 0, 2)
	if thread, ok := representativeThread(producer.threads); ok {
		threads = append(threads, &thread)
	}
	if thread, ok := representativeThread(consumer.threads); ok {
		threads = append(threads, &thread)
	}
	return threads
}

func representativeThreadsForMounts(producer, consumer podContainerFacts, producerMounts, consumerMounts []containerMountFact) []*target.Thread {
	threads := make([]*target.Thread, 0, 2)
	if thread, ok := representativeThreadInNamespaces(producer.threads, mountNamespaces(producerMounts)); ok {
		threads = append(threads, &thread)
	}
	if thread, ok := representativeThreadInNamespaces(consumer.threads, mountNamespaces(consumerMounts)); ok {
		threads = append(threads, &thread)
	}
	return threads
}

func representativeThreadInNamespaces(threads []target.Thread, namespaces []target.NSRef) (target.Thread, bool) {
	if len(namespaces) == 0 {
		return representativeThread(threads)
	}
	for _, thread := range threads {
		if (thread.IsMainThread || (thread.Tid != 0 && thread.Tid == thread.Tgid)) && slices.Contains(namespaces, thread.MntNS) {
			return thread, true
		}
	}
	for _, thread := range threads {
		if slices.Contains(namespaces, thread.MntNS) {
			return thread, true
		}
	}
	return representativeThread(threads)
}

func representativeThread(threads []target.Thread) (target.Thread, bool) {
	if len(threads) == 0 {
		return target.Thread{}, false
	}
	for _, thread := range threads {
		if thread.IsMainThread || (thread.Tid != 0 && thread.Tid == thread.Tgid) {
			return thread, true
		}
	}
	return threads[0], true
}

func mountNamespaces(mounts []containerMountFact) []target.NSRef {
	refs := make([]target.NSRef, 0, len(mounts))
	seen := make(map[target.NSRef]struct{})
	for _, mount := range mounts {
		if isZeroNamespace(mount.namespace) {
			continue
		}
		if _, ok := seen[mount.namespace]; ok {
			continue
		}
		seen[mount.namespace] = struct{}{}
		refs = append(refs, mount.namespace)
	}
	return refs
}

func producerCapabilityAmplifiers(input PodContainerAnalysis) []string {
	seen := make(map[string]struct{})
	amplifiers := make([]string, 0)
	for _, finding := range capabilityFindings(input) {
		name, ok := volumeCapabilityAmplifier(finding)
		if !ok {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		amplifiers = append(amplifiers, name)
	}
	slices.Sort(amplifiers)
	return amplifiers
}

func capabilityFindings(input PodContainerAnalysis) []*model.Finding {
	if len(input.Signals) > 0 {
		findings := make([]*model.Finding, 0, len(input.Signals))
		for i := range input.Signals {
			if input.Signals[i].Category != "capabilities" {
				continue
			}
			findings = append(findings, &input.Signals[i].Finding)
		}
		return findings
	}
	return input.Findings
}

func sharedVolumeSummary(producer, consumer model.ContainerContext, consumerMountPoints, amplifiers []string) string {
	summary := fmt.Sprintf(
		"Container %s has writable access to a shared backing source that container %s mounts at sensitive path(s) %s, so the producer can modify files consumed through the consumer's sensitive filesystem view.",
		readableContainerName(producer),
		readableContainerName(consumer),
		strings.Join(consumerMountPoints, ", "),
	)
	if len(amplifiers) > 0 {
		summary += fmt.Sprintf(" Producer also has effective/permitted capability amplifiers: %s, which may make ownership, permission, or file-capability changes more impactful.", strings.Join(amplifiers, ", "))
	}
	return summary
}

func sharedVolumeEvidence(
	producer, consumer podContainerFacts,
	sourceKey backingSourceKey,
	producerMounts, consumerMounts []containerMountFact,
	amplifiers []string,
	relativeThreads []*target.Thread,
) []string {
	evidence := []string{
		fmt.Sprintf("producer container=%s", readableContainerName(producer.context)),
		fmt.Sprintf("consumer container=%s", readableContainerName(consumer.context)),
		fmt.Sprintf("backing source key: fstype=%s, source=%s, root=%s", sourceKey.FSType, sourceKey.Source, sourceKey.Root),
		fmt.Sprintf("producer writable mount points=%s", strings.Join(uniqueMountPoints(producerMounts), ", ")),
		fmt.Sprintf("consumer sensitive mount points=%s", strings.Join(uniqueMountPoints(consumerMounts), ", ")),
		fmt.Sprintf("producer mount namespaces=%s", strings.Join(formatMountNamespaces(producerMounts), ", ")),
		fmt.Sprintf("consumer mount namespaces=%s", strings.Join(formatMountNamespaces(consumerMounts), ", ")),
		fmt.Sprintf("consumer mount read-write states=%s", strings.Join(formatMountWritableStates(consumerMounts), ", ")),
	}
	if len(relativeThreads) > 0 {
		evidence = append(evidence, "representative threads="+formatRepresentativeThreads(relativeThreads))
	}
	if len(amplifiers) > 0 {
		evidence = append(evidence, "producer effective/permitted capability amplifiers="+strings.Join(amplifiers, ", "))
	} else {
		evidence = append(evidence, "producer effective/permitted capability amplifiers=none observed")
	}
	return evidence
}

func formatMountNamespaces(mounts []containerMountFact) []string {
	refs := relatedMountNamespaces(mounts, nil)
	formatted := make([]string, 0, len(refs))
	for _, ref := range refs {
		formatted = append(formatted, formatNSRef(ref))
	}
	return formatted
}

func formatMountWritableStates(mounts []containerMountFact) []string {
	states := make([]string, 0, len(mounts))
	for _, mount := range mounts {
		state := "ro"
		if mount.writable {
			state = "rw"
		}
		states = append(states, fmt.Sprintf("%s=%s", mount.mountPoint, state))
	}
	return states
}

func formatRepresentativeThreads(threads []*target.Thread) string {
	parts := make([]string, 0, len(threads))
	for _, thread := range threads {
		if thread == nil {
			continue
		}
		parts = append(parts, fmt.Sprintf("tid=%d/tgid=%d", thread.Tid, thread.Tgid))
	}
	return strings.Join(parts, ", ")
}

func containerAnalysisKey(snapshot model.Snapshot) string {
	switch {
	case strings.TrimSpace(snapshot.ContainerID) != "":
		return "id:" + strings.TrimSpace(snapshot.ContainerID)
	case strings.TrimSpace(snapshot.RuntimeID) != "":
		return "runtime:" + strings.TrimSpace(snapshot.Runtime) + ":" + strings.TrimSpace(snapshot.RuntimeID)
	case strings.TrimSpace(snapshot.ContainerName) != "":
		return "name:" + strings.TrimSpace(snapshot.Namespace) + "/" + strings.TrimSpace(snapshot.PodName) + "/" + strings.TrimSpace(snapshot.ContainerName)
	case snapshot.InitPID != 0:
		return fmt.Sprintf("pid:%d", snapshot.InitPID)
	default:
		return ""
	}
}

func readableContainerName(context model.ContainerContext) string {
	if context.Name != "" {
		return context.Name
	}
	if context.ContainerID != "" {
		return context.ContainerID
	}
	if context.RuntimeID != "" {
		return context.RuntimeID
	}
	if context.InitPID != 0 {
		return fmt.Sprintf("pid:%d", context.InitPID)
	}
	return "unknown"
}

func isZeroNamespace(ns target.NSRef) bool {
	return ns.Type == "" && ns.Dev == 0 && ns.Ino == 0
}
