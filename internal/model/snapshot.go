package model

import (
	"strconv"
	"time"

	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

type NamespaceSnapshot struct {
	target.NSRef
	Owner      target.NSRef
	MountInfo  []collect.MountInfo
	OwnerKnown bool
}

type ThreadSnapshot target.Thread

type Metadata struct {
	CollectedAt time.Time
	ContainerID string
	InitPID     int
	CgroupPath  string
}

type Snapshot struct {
	// metadata about the container and the collecting operation
	Metadata
	// namespaces collected
	MountNamespaces []NamespaceSnapshot
	PIDNamespaces   []NamespaceSnapshot
	UserNamespaces  []NamespaceSnapshot
	// threads collected, including seccomp, capabilities, etc.
	Threads map[int]ThreadSnapshot
	// abnormal events on scanning, like thread exiting half way
	Warnings []string
}

func initSnapshot() Snapshot {
	return Snapshot{}
}

func (s *Snapshot) collectMetadata(metadata Metadata) {
	s.CollectedAt = metadata.CollectedAt
	s.ContainerID = metadata.ContainerID
	s.InitPID = metadata.InitPID
	s.CgroupPath = metadata.CgroupPath
}

func (s *Snapshot) collectNS() {
	for mntns := range collect.MntNSThreads {
		owner, ok := collect.OwnerUserNSByNS[mntns]
		s.MountNamespaces = append(s.MountNamespaces, NamespaceSnapshot{mntns, owner, collect.MntNSInfo[mntns], ok && owner.Type == "user"})
	}
	for pidns := range collect.PIDNSThreads {
		owner, ok := collect.OwnerUserNSByNS[pidns]
		s.PIDNamespaces = append(s.PIDNamespaces, NamespaceSnapshot{pidns, owner, nil, ok && owner.Type == "user"})
	}
	for userns := range collect.UserNSThreads {
		s.UserNamespaces = append(s.UserNamespaces, NamespaceSnapshot{userns, userns, nil, true})
	}
}

func (s *Snapshot) collectThreads(threads map[int]*target.Thread) {
	s.Threads = make(map[int]ThreadSnapshot)
	for tid, thread := range threads {
		s.Threads[tid] = ThreadSnapshot(*thread)
	}
}

func makeCollections(threads map[int]*target.Thread, s *Snapshot) {
	err := collect.ClctCapabilities(threads)
	if err != nil {
		s.Warnings = append(s.Warnings, "On Collecting capabilities: "+err.Error())
	}
	err = collect.ClctSeccomp(threads)
	if err != nil {
		s.Warnings = append(s.Warnings, "On Collecting seccomp: "+err.Error())
	}
	for _, thread := range threads {
		err = collect.ClctNamespace(thread)
		if err != nil {
			s.Warnings = append(s.Warnings, "On Collecting thread (tid: "+strconv.Itoa(thread.Tid)+", thread comm: "+thread.Comm+"): "+err.Error())
		}
	}
	err = collect.ClctMountInfo()
	if err != nil {
		s.Warnings = append(s.Warnings, "On Collecting mountinfo: "+err.Error())
	}
	err = collect.ClctHostNamespace()
	if err != nil {
		s.Warnings = append(s.Warnings, "On Collecting Host namespaces: "+err.Error())
	}
}

func DoSnapshot(metadata Metadata) (Snapshot, error) {
	threads, err := target.RetrieveAllThreads(metadata.CgroupPath)
	if err != nil {
		return Snapshot{}, err
	}
	var s = initSnapshot()
	// 0. do collections
	makeCollections(threads, &s)
	// 1. collect metadata
	s.collectMetadata(metadata)
	// 2. collect namespace information
	s.collectNS()
	// 3. collect threads
	s.collectThreads(threads)
	return s, nil
}
