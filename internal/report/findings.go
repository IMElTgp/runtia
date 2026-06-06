package report

import "github.com/IMElTgp/container-runtime-analysis/internal/model"

// GenerateFindings converts uncovered analyzer signals into report findings.
// Covered primitive signals are still available to later composition stages
// through raw signals, but they are not emitted as standalone findings here.
func GenerateFindings(signals []model.Signal) (findings []*model.Finding) {
	for _, sig := range signals {
		if sig.Covered {
			continue
		}
		findings = append(findings, &model.Finding{
			Category:        sig.Category,
			Recommendation:  sig.Recommendation,
			Namespace:       sig.Namespace,
			PodName:         sig.PodName,
			NodeName:        sig.NodeName,
			Containers:      sig.Containers,
			RelativeThreads: sig.RelativeThreads,
			RelativeNS:      sig.RelativeNS,
			RelativeNSs:     sig.RelativeNSs,
			RiskLevel:       sig.RiskLevel,
			Summary:         sig.Summary,
			Title:           sig.Title,
			Evidence:        sig.Evidence,
			MountPoint:      sig.MountPoint,
		})
	}

	return
}
