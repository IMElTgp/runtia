package model

import (
	"fmt"
	"slices"
	"strings"

	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

type ContainerContext struct {
	Name               string         `json:"Name,omitempty"`
	ContainerID        string         `json:"ContainerID,omitempty"`
	Runtime            string         `json:"Runtime,omitempty"`
	RuntimeID          string         `json:"RuntimeID,omitempty"`
	InitPID            int            `json:"InitPID,omitempty"`
	CgroupPath         string         `json:"CgroupPath,omitempty"`
	UserNamespaces     []target.NSRef `json:"UserNamespaces,omitempty"`
	PIDNamespaces      []target.NSRef `json:"PIDNamespaces,omitempty"`
	MountNamespaces    []target.NSRef `json:"MountNamespaces,omitempty"`
	MainUserNamespace  *target.NSRef  `json:"MainUserNamespace,omitempty"`
	MainPIDNamespace   *target.NSRef  `json:"MainPIDNamespace,omitempty"`
	MainMountNamespace *target.NSRef  `json:"MainMountNamespace,omitempty"`
}

type Warning struct {
	Namespace     string `json:"Namespace,omitempty"`
	PodName       string `json:"PodName,omitempty"`
	NodeName      string `json:"NodeName,omitempty"`
	ContainerName string `json:"ContainerName,omitempty"`
	ContainerID   string `json:"ContainerID,omitempty"`
	Stage         string `json:"Stage,omitempty"`
	Message       string `json:"Message,omitempty"`
}

type Finding struct {
	Category        string // "namespace", "seccomp", "capabilities", "mount"
	RiskLevel       int    // Fatal, HighRisk, MediumRisk, LowRisk, Info
	Title           string
	Summary         string
	Evidence        []string
	Namespace       string             `json:"Namespace,omitempty"`
	PodName         string             `json:"PodName,omitempty"`
	NodeName        string             `json:"NodeName,omitempty"`
	Containers      []ContainerContext `json:"Containers,omitempty"`
	RelativeThreads []*target.Thread
	RelativeNS      *target.NSRef
	RelativeNSs     []target.NSRef `json:"RelativeNSs,omitempty"`
	MountPoint      []string
	Recommendation  string
}

func ContainerContextFromMetadata(metadata Metadata) ContainerContext {
	return ContainerContext{
		Name:        metadata.ContainerName,
		ContainerID: metadata.ContainerID,
		Runtime:     metadata.Runtime,
		RuntimeID:   metadata.RuntimeID,
		InitPID:     metadata.InitPID,
		CgroupPath:  metadata.CgroupPath,
	}
}

func ContainerContextFromSnapshot(snapshot Snapshot) ContainerContext {
	context := ContainerContextFromMetadata(snapshot.Metadata)
	context.UserNamespaces = namespaceRefsFromSnapshots(snapshot.UserNamespaces)
	context.PIDNamespaces = namespaceRefsFromSnapshots(snapshot.PIDNamespaces)
	context.MountNamespaces = namespaceRefsFromSnapshots(snapshot.MountNamespaces)

	if main := mainThreadFromSnapshot(snapshot); main != nil {
		thread := target.Thread(*main)
		if !isZeroNSRef(thread.UserNS) {
			ns := thread.UserNS
			context.MainUserNamespace = &ns
		}
		if !isZeroNSRef(thread.PIDNS) {
			ns := thread.PIDNS
			context.MainPIDNamespace = &ns
		}
		if !isZeroNSRef(thread.MntNS) {
			ns := thread.MntNS
			context.MainMountNamespace = &ns
		}
	}

	return context
}

func namespaceRefsFromSnapshots(namespaces []NamespaceSnapshot) []target.NSRef {
	if len(namespaces) == 0 {
		return nil
	}

	seen := make(map[target.NSRef]struct{}, len(namespaces))
	refs := make([]target.NSRef, 0, len(namespaces))
	for _, namespace := range namespaces {
		ref := namespace.NSRef
		if isZeroNSRef(ref) {
			continue
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	sortNSRefs(refs)
	return refs
}

func mainThreadFromSnapshot(snapshot Snapshot) *ThreadSnapshot {
	if len(snapshot.Threads) == 0 {
		return nil
	}
	if snapshot.InitPID != 0 {
		if thread, ok := snapshot.Threads[snapshot.InitPID]; ok {
			return &thread
		}
	}
	for _, thread := range snapshot.Threads {
		t := target.Thread(thread)
		if t.IsMainThread {
			threadCopy := thread
			return &threadCopy
		}
	}
	return nil
}

func sortNSRefs(refs []target.NSRef) {
	for i := 1; i < len(refs); i++ {
		cur := refs[i]
		j := i - 1
		for j >= 0 && lessNSRef(cur, refs[j]) {
			refs[j+1] = refs[j]
			j--
		}
		refs[j+1] = cur
	}
}

func lessNSRef(a, b target.NSRef) bool {
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if a.Dev != b.Dev {
		return a.Dev < b.Dev
	}
	return a.Ino < b.Ino
}

func isZeroNSRef(ns target.NSRef) bool {
	return ns.Type == "" && ns.Dev == 0 && ns.Ino == 0
}

func AttachContextToFindings(findings []*Finding, metadata Metadata) {
	attachContainerContextToFindings(findings, metadata, ContainerContextFromMetadata(metadata))
}

func AttachSnapshotContextToFindings(findings []*Finding, snapshot Snapshot) {
	attachContainerContextToFindings(findings, snapshot.Metadata, ContainerContextFromSnapshot(snapshot))
}

func attachContainerContextToFindings(findings []*Finding, metadata Metadata, container ContainerContext) {
	for _, finding := range findings {
		if finding == nil {
			continue
		}

		if finding.Namespace == "" {
			finding.Namespace = metadata.Namespace
		}
		if finding.PodName == "" {
			finding.PodName = metadata.PodName
		}
		if finding.NodeName == "" {
			finding.NodeName = metadata.NodeName
		}

		addedContainer := false
		if !containsContainerContext(finding.Containers, container) && !isEmptyContainerContext(container) {
			finding.Containers = append(finding.Containers, container)
			addedContainer = true
		}

		if addedContainer {
			prependContextEvidenceOnce(finding, metadata, container)
		}
	}
}

func containsContainerContext(containers []ContainerContext, target ContainerContext) bool {
	for _, container := range containers {
		if sameContainerContext(container, target) {
			return true
		}
	}
	return false
}

func sameContainerContext(a, b ContainerContext) bool {
	if a.ContainerID != "" || b.ContainerID != "" {
		return a.ContainerID != "" && a.ContainerID == b.ContainerID
	}
	if a.RuntimeID != "" || b.RuntimeID != "" {
		return a.Runtime == b.Runtime && a.RuntimeID != "" && a.RuntimeID == b.RuntimeID
	}
	if a.Name != "" || b.Name != "" {
		return a.Name != "" && a.Name == b.Name && (a.InitPID == 0 || b.InitPID == 0 || a.InitPID == b.InitPID)
	}
	if a.InitPID != 0 || b.InitPID != 0 {
		return a.InitPID != 0 && a.InitPID == b.InitPID
	}
	return a.CgroupPath != "" && a.CgroupPath == b.CgroupPath
}

func isEmptyContainerContext(container ContainerContext) bool {
	return container.Name == "" &&
		container.ContainerID == "" &&
		container.Runtime == "" &&
		container.RuntimeID == "" &&
		container.InitPID == 0 &&
		container.CgroupPath == "" &&
		len(container.UserNamespaces) == 0 &&
		len(container.PIDNamespaces) == 0 &&
		len(container.MountNamespaces) == 0 &&
		container.MainUserNamespace == nil &&
		container.MainPIDNamespace == nil &&
		container.MainMountNamespace == nil
}

func prependContextEvidenceOnce(finding *Finding, metadata Metadata, container ContainerContext) {
	podEvidence := formatPodEvidence(metadata)
	containerEvidence := formatContainerEvidence(container)
	if hasEvidence(finding.Evidence, podEvidence) && hasEvidence(finding.Evidence, containerEvidence) {
		return
	}

	contextEvidence := make([]string, 0, 2)
	if podEvidence != "" && !hasEvidence(finding.Evidence, podEvidence) {
		contextEvidence = append(contextEvidence, podEvidence)
	}
	if containerEvidence != "" && !hasEvidence(finding.Evidence, containerEvidence) {
		contextEvidence = append(contextEvidence, containerEvidence)
	}
	if len(contextEvidence) == 0 {
		return
	}

	finding.Evidence = append(contextEvidence, finding.Evidence...)
}

func formatPodEvidence(metadata Metadata) string {
	if metadata.Namespace == "" && metadata.PodName == "" && metadata.NodeName == "" {
		return ""
	}

	pod := metadata.PodName
	if metadata.Namespace != "" || metadata.PodName != "" {
		pod = metadata.Namespace + "/" + metadata.PodName
	}
	if metadata.NodeName == "" {
		return "pod=" + pod
	}
	return fmt.Sprintf("pod=%s, node=%s", pod, metadata.NodeName)
}

func formatContainerEvidence(container ContainerContext) string {
	parts := make([]string, 0, 6)
	if container.Name != "" {
		parts = append(parts, "container name="+container.Name)
	}
	if container.ContainerID != "" {
		parts = append(parts, "id="+container.ContainerID)
	}
	if container.Runtime != "" {
		parts = append(parts, "runtime="+container.Runtime)
	}
	if container.RuntimeID != "" {
		parts = append(parts, "runtime_id="+container.RuntimeID)
	}
	if container.InitPID != 0 {
		parts = append(parts, fmt.Sprintf("init_pid=%d", container.InitPID))
	}
	if container.CgroupPath != "" {
		parts = append(parts, "cgroup="+container.CgroupPath)
	}
	return strings.Join(parts, ", ")
}

func hasEvidence(evidence []string, target string) bool {
	if target == "" {
		return true
	}
	return slices.Contains(evidence, target)
}
