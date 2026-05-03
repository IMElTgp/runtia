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
	namespaceFindings    []*model.Finding
	seccompFindings      []*model.Finding
	mountFindings        []*model.Finding
	capabilitiesFindings []*model.Finding
)

// fill above findings by category
func fillFindings(findings []*model.Finding) {
	for _, finding := range findings {
		switch finding.Category {
		case "namespace":
			namespaceFindings = append(namespaceFindings, finding)
		case "seccomp":
			seccompFindings = append(seccompFindings, finding)
		case "mount":
			mountFindings = append(mountFindings, finding)
		case "capabilities":
			capabilitiesFindings = append(capabilitiesFindings, finding)
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

// sortNamespaceFindings sorts namespace-related findings
// according 4 rules (with descending priorities)
func sortNamespaceFindings() {
	namespaceFindings = removeDuplicates(namespaceFindings)
	sort.Slice(namespaceFindings, func(i, j int) bool {
		if namespaceFindings[i].RiskLevel != namespaceFindings[j].RiskLevel {
			// rule1 (highest priority): risk level (decreasing)
			return namespaceFindings[i].RiskLevel > namespaceFindings[j].RiskLevel
		} else if namespaceFindings[i].RelativeNS.Type != namespaceFindings[j].RelativeNS.Type {
			// rule2: type (user > pid > mnt)
			return nsTypeRank(namespaceFindings[i].RelativeNS, namespaceFindings[j].RelativeNS)
		} else if namespaceFindings[i].RelativeNS.Dev != namespaceFindings[j].RelativeNS.Dev {
			// rule3: dev
			return namespaceFindings[i].RelativeNS.Dev < namespaceFindings[j].RelativeNS.Dev
		}
		// rule4: ino
		return namespaceFindings[i].RelativeNS.Ino < namespaceFindings[j].RelativeNS.Ino
	})
}

// sortSeccompFindings sorts seccomp-related findings
func sortSeccompFindings() {
	seccompFindings = removeDuplicates(seccompFindings)
	sort.Slice(seccompFindings, func(i, j int) bool {
		if seccompFindings[i].RiskLevel != seccompFindings[j].RiskLevel {
			// rule1: risk level
			return seccompFindings[i].RiskLevel > seccompFindings[j].RiskLevel
		} else if seccompFindings[i].RelativeThreads[0].Tgid != seccompFindings[j].RelativeThreads[0].Tgid {
			// rule2: tgid
			return seccompFindings[i].RelativeThreads[0].Tgid < seccompFindings[j].RelativeThreads[0].Tgid
		}
		// rule3: tid
		return seccompFindings[i].RelativeThreads[0].Tid < seccompFindings[j].RelativeThreads[0].Tid
	})
}

// sortMountFindings sorts mount-related findings
func sortMountFindings() {
	mountFindings = removeDuplicates(mountFindings)
	sort.Slice(mountFindings, func(i, j int) bool {
		if mountFindings[i].RiskLevel != mountFindings[j].RiskLevel {
			// rule1: risk level
			return mountFindings[i].RiskLevel > mountFindings[j].RiskLevel
		}
		// rule2: mountpoint (in alphabet order)
		return util.JoinStringSlice(mountFindings[i].MountPoint) < util.JoinStringSlice(mountFindings[j].MountPoint)
	})
}

// sortCapabilitiesFindings sorts capabilities-related findings
func sortCapabilitiesFindings() {
	capabilitiesFindings = removeDuplicates(capabilitiesFindings)
	sort.Slice(capabilitiesFindings, func(i, j int) bool {
		if capabilitiesFindings[i].RiskLevel != capabilitiesFindings[j].RiskLevel {
			// rule1: risk level
			return capabilitiesFindings[i].RiskLevel > capabilitiesFindings[j].RiskLevel
		} else if analyze.ParseCapabilityNameFromFinding(capabilitiesFindings[i]) != analyze.ParseCapabilityNameFromFinding(capabilitiesFindings[j]) {
			// rule2: capability type (alphabet order)
			return analyze.ParseCapabilityNameFromFinding(capabilitiesFindings[i]) < analyze.ParseCapabilityNameFromFinding(capabilitiesFindings[j])
		} else if capabilitiesFindings[i].RelativeThreads[0].Tgid != capabilitiesFindings[j].RelativeThreads[0].Tgid {
			// rule3: tgid
			return capabilitiesFindings[i].RelativeThreads[0].Tgid < capabilitiesFindings[j].RelativeThreads[0].Tgid
		}
		// rule4: tid
		return capabilitiesFindings[i].RelativeThreads[0].Tid < capabilitiesFindings[j].RelativeThreads[0].Tid
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
	namespaceFindings = []*model.Finding{}
	seccompFindings = []*model.Finding{}
	mountFindings = []*model.Finding{}
	capabilitiesFindings = []*model.Finding{}

	fillFindings(findings)

	sortNamespaceFindings()
	sortSeccompFindings()
	sortMountFindings()
	sortCapabilitiesFindings()
}
