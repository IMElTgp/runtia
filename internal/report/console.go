package report

import (
	"fmt"
	"strings"

	"github.com/IMElTgp/container-runtime-analysis/internal/analyze"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
)

/**
 * console.go
 * print the findings to the terminal
 * from every category, print certain amount of high level risks
 */

const (
	maxRepresentativePerCategory = 2
	maxRepresentativeTotal       = 6
)

func riskLevelLabel(risk int) string {
	switch risk {
	case analyze.Fatal:
		return "Fatal"
	case analyze.HighRisk:
		return "HighRisk"
	case analyze.MediumRisk:
		return "MediumRisk"
	case analyze.LowRisk:
		return "LowRisk"
	case analyze.Info:
		return "Info"
	default:
		return fmt.Sprintf("%d", risk)
	}
}

// printOneFinding determines how to print one finding to the terminal
func printOneFinding(finding *model.Finding) {
	fmt.Println("Risk Category:", finding.Category)
	fmt.Println("Risk Level:", riskLevelLabel(finding.RiskLevel))
	fmt.Println("Finding Title:", finding.Title)
	if finding.Summary != "" {
		fmt.Println("Summary:", finding.Summary)
	}
	if len(finding.Evidence) > 0 {
		fmt.Println("Evidences:")
		for _, evidence := range finding.Evidence {
			fmt.Println(" ", evidence)
		}
	}
	if len(finding.RelativeThreads) > 0 {
		fmt.Println("Related Threads:")
		for _, thread := range finding.RelativeThreads {
			fmt.Print("  ")
			fmt.Print(fmt.Sprintf("tid=%d, comm=%s, ", thread.Tid, strings.TrimSpace(thread.Comm)))
			if thread.IsMainThread {
				fmt.Println("is main thread: yes")
			} else {
				fmt.Println("is main thread: no")
			}
		}
	}
	if finding.RelativeNS != nil {
		fmt.Println("Related Namespace:", fmt.Sprintf("dev=%d, ino=%d, type=%s", finding.RelativeNS.Dev, finding.RelativeNS.Ino, finding.RelativeNS.Type))
	}
	if len(finding.MountPoint) > 0 {
		fmt.Println("Mount Points:", strings.Join(finding.MountPoint, " "))
	}
	if finding.Recommendation != "" {
		fmt.Println("Hardening recommendation:", finding.Recommendation)
	}
}

// only print risks of Fatal/HighRisk risk level
func isRepresentativeRisk(finding *model.Finding) bool {
	return finding != nil && (finding.RiskLevel == analyze.Fatal || finding.RiskLevel == analyze.HighRisk)
}

// countByRisk counts the frequency of each risk level
func countByRisk(findings []*model.Finding, risk int) int {
	count := 0
	for _, finding := range findings {
		if finding != nil && finding.RiskLevel == risk {
			count++
		}
	}
	return count
}

// pickRepresentativeFindings picks at most 2 findings of each category
func pickRepresentativeFindings(findings []*model.Finding, limit int) []*model.Finding {
	if limit <= 0 {
		return nil
	}
	picked := make([]*model.Finding, 0, limit)
	for _, finding := range findings {
		if !isRepresentativeRisk(finding) {
			continue
		}
		picked = append(picked, finding)
		if len(picked) == limit {
			break
		}
	}
	return picked
}

func PrintToTerminal(exampleFindings []*model.Finding) {
	if len(exampleFindings) == 0 {
		fmt.Println("No findings.")
		return
	}

	SortFindingsByCategory(exampleFindings)

	// count the frequency of each risk level
	fmt.Println("Findings Summary:")
	fmt.Println(" Fatal:", countByRisk(exampleFindings, analyze.Fatal))
	fmt.Println(" HighRisk:", countByRisk(exampleFindings, analyze.HighRisk))
	fmt.Println(" MediumRisk:", countByRisk(exampleFindings, analyze.MediumRisk))
	fmt.Println(" LowRisk:", countByRisk(exampleFindings, analyze.LowRisk))
	fmt.Println(" Info:", countByRisk(exampleFindings, analyze.Info))

	// pick at most 6 findings as representative findings
	selected := make([]*model.Finding, 0, maxRepresentativeTotal)
	categories := [][]*model.Finding{
		namespaceFindings,
		seccompFindings,
		capabilitiesFindings,
		mountFindings,
	}
	// for each category, pick representative findings separately
	for _, findings := range categories {
		for _, finding := range pickRepresentativeFindings(findings, maxRepresentativePerCategory) {
			selected = append(selected, finding)
			if len(selected) == maxRepresentativeTotal {
				break
			}
		}
		if len(selected) == maxRepresentativeTotal {
			break
		}
	}

	if len(selected) == 0 {
		fmt.Println()
		fmt.Println("No Fatal/HighRisk findings to highlight in terminal.")
		return
	}

	fmt.Println()
	fmt.Println("Representative Fatal/HighRisk Findings:")
	for i, finding := range selected {
		fmt.Println()
		fmt.Printf("[%d/%d]\n", i+1, len(selected))
		printOneFinding(finding)
	}
	fmt.Println("See all findings in ./namespace.json, ./mount.json, ./seccomp.json or ./capabilities.json. If one of those files doesn't exist, that means there's no risk of that category that is found.")
}
