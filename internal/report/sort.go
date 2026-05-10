package report

import (
	"sort"

	"github.com/IMElTgp/container-runtime-analysis/internal/analyze"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
	"github.com/IMElTgp/container-runtime-analysis/internal/util"
)

/**
 * sort.go
 * sort all findings by severity
 */

// store findings by categories
var (
	CompositionFindings  = make([]*model.Finding, 0)
	NamespaceFindings    = make([]*model.Finding, 0)
	SeccompFindings      = make([]*model.Finding, 0)
	MountFindings        = make([]*model.Finding, 0)
	CapabilitiesFindings = make([]*model.Finding, 0)
)

// fill above findings by category
func fillFindings(findings []*model.Finding) {
	for _, finding := range findings {
		switch finding.Category {
		case "composition":
			CompositionFindings = append(CompositionFindings, finding)
		case "namespace":
			NamespaceFindings = append(NamespaceFindings, finding)
		case "seccomp":
			SeccompFindings = append(SeccompFindings, finding)
		case "mount":
			MountFindings = append(MountFindings, finding)
		case "capabilities":
			CapabilitiesFindings = append(CapabilitiesFindings, finding)
		default:
			// for further composition
		}
	}
}

// removeDuplicates removes duplicate findings
func removeDuplicates(findings []*model.Finding) (noDup []*model.Finding) {
	// use {evidence, title, risklevel} triple tuple as identifier
	type identifier struct {
		joinedEvidence string
		title          string
		riskLevel      int
	}
	// use a map to remove duplicate findings
	tmp := make(map[identifier]*model.Finding)
	for _, finding := range findings {
		id := identifier{
			joinedEvidence: util.JoinStringSlice(finding.Evidence),
			title:          finding.Title,
			riskLevel:      finding.RiskLevel,
		}
		tmp[id] = finding
	}
	for _, finding := range tmp {
		noDup = append(noDup, finding)
	}
	return
}

// nsTypeRank returns true when ns1 is designed to be ranked
// lower than ns2 (i.e. ns1 is in front of ns2 after sorting)
func nsTypeRank(ns1, ns2 *target.NSRef) bool {
	if ns1 == nil {
		return false
	}
	if ns2 == nil {
		return true
	}

	switch ns1.Type {
	case "user":
		return true
	case "pid":
		if ns2.Type != "user" {
			return true
		}
		return false
	default:
		return false
	}
}

func sortCompositionFindings() {
	CompositionFindings = removeDuplicates(CompositionFindings)
	sort.Slice(CompositionFindings, func(i, j int) bool {
		if CompositionFindings[i].RiskLevel != CompositionFindings[j].RiskLevel {
			return CompositionFindings[i].RiskLevel > CompositionFindings[j].RiskLevel
		}
		return CompositionFindings[i].Title < CompositionFindings[j].Title
	})
}

// sortNamespaceFindings sorts namespace-related findings
// according 4 rules (with descending priorities)
func sortNamespaceFindings() {
	NamespaceFindings = removeDuplicates(NamespaceFindings)
	sort.Slice(NamespaceFindings, func(i, j int) bool {
		if NamespaceFindings[i].RiskLevel != NamespaceFindings[j].RiskLevel {
			// rule1 (highest priority): risk level (decreasing)
			return NamespaceFindings[i].RiskLevel > NamespaceFindings[j].RiskLevel
		} else if NamespaceFindings[i].RelativeNS.Type != NamespaceFindings[j].RelativeNS.Type {
			// rule2: type (user > pid > mnt)
			return nsTypeRank(NamespaceFindings[i].RelativeNS, NamespaceFindings[j].RelativeNS)
		} else if NamespaceFindings[i].RelativeNS.Dev != NamespaceFindings[j].RelativeNS.Dev {
			// rule3: dev
			return NamespaceFindings[i].RelativeNS.Dev < NamespaceFindings[j].RelativeNS.Dev
		}
		// rule4: ino
		return NamespaceFindings[i].RelativeNS.Ino < NamespaceFindings[j].RelativeNS.Ino
	})
}

// sortSeccompFindings sorts seccomp-related findings
func sortSeccompFindings() {
	SeccompFindings = removeDuplicates(SeccompFindings)
	sort.Slice(SeccompFindings, func(i, j int) bool {
		if SeccompFindings[i].RiskLevel != SeccompFindings[j].RiskLevel {
			// rule1: risk level
			return SeccompFindings[i].RiskLevel > SeccompFindings[j].RiskLevel
		} else if SeccompFindings[i].RelativeThreads[0].Tgid != SeccompFindings[j].RelativeThreads[0].Tgid {
			// rule2: tgid
			return SeccompFindings[i].RelativeThreads[0].Tgid < SeccompFindings[j].RelativeThreads[0].Tgid
		}
		// rule3: tid
		return SeccompFindings[i].RelativeThreads[0].Tid < SeccompFindings[j].RelativeThreads[0].Tid
	})
}

// sortMountFindings sorts mount-related findings
func sortMountFindings() {
	MountFindings = removeDuplicates(MountFindings)
	sort.Slice(MountFindings, func(i, j int) bool {
		if MountFindings[i].RiskLevel != MountFindings[j].RiskLevel {
			// rule1: risk level
			return MountFindings[i].RiskLevel > MountFindings[j].RiskLevel
		}
		// rule2: mountpoint (in alphabet order)
		return util.JoinStringSlice(MountFindings[i].MountPoint) < util.JoinStringSlice(MountFindings[j].MountPoint)
	})
}

// sortCapabilitiesFindings sorts capabilities-related findings
func sortCapabilitiesFindings() {
	CapabilitiesFindings = removeDuplicates(CapabilitiesFindings)
	sort.Slice(CapabilitiesFindings, func(i, j int) bool {
		if CapabilitiesFindings[i].RiskLevel != CapabilitiesFindings[j].RiskLevel {
			// rule1: risk level
			return CapabilitiesFindings[i].RiskLevel > CapabilitiesFindings[j].RiskLevel
		} else if analyze.ParseCapabilityNameFromFinding(CapabilitiesFindings[i]) != analyze.ParseCapabilityNameFromFinding(CapabilitiesFindings[j]) {
			// rule2: capability type (alphabet order)
			return analyze.ParseCapabilityNameFromFinding(CapabilitiesFindings[i]) < analyze.ParseCapabilityNameFromFinding(CapabilitiesFindings[j])
		} else if CapabilitiesFindings[i].RelativeThreads[0].Tgid != CapabilitiesFindings[j].RelativeThreads[0].Tgid {
			// rule3: tgid
			return CapabilitiesFindings[i].RelativeThreads[0].Tgid < CapabilitiesFindings[j].RelativeThreads[0].Tgid
		}
		// rule4: tid
		return CapabilitiesFindings[i].RelativeThreads[0].Tid < CapabilitiesFindings[j].RelativeThreads[0].Tid
	})
}

// SortFindings sorts the whole finding slice (DEPRECATED)
func SortFindings(findings []*model.Finding) []*model.Finding {
	findings = removeDuplicates(findings)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RiskLevel != findings[j].RiskLevel {
			return findings[i].RiskLevel > findings[j].RiskLevel
		} else if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		return findings[i].Title < findings[j].Title
	})
	return findings
}

// SortFindingsByCategory sorts findings separately by category
func SortFindingsByCategory(findings []*model.Finding) {
	// clear all finding slices before filling
	CompositionFindings = []*model.Finding{}
	NamespaceFindings = []*model.Finding{}
	SeccompFindings = []*model.Finding{}
	MountFindings = []*model.Finding{}
	CapabilitiesFindings = []*model.Finding{}

	fillFindings(findings)

	sortCompositionFindings()
	sortNamespaceFindings()
	sortSeccompFindings()
	sortMountFindings()
	sortCapabilitiesFindings()
}
