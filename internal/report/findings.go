package report

import "github.com/IMElTgp/container-runtime-analysis/internal/model"

// findings.go converts signals to findings
// just turn model.Signal into model.Finding

func GenerateFindings(signals []model.Signal) (findings []*model.Finding) {
	for _, sig := range signals {
		if sig.Covered {
			continue
		}
		findings = append(findings, &model.Finding{
			Category:        sig.Category,
			Recommendation:  sig.Recommendation,
			RelativeThreads: sig.RelativeThreads,
			RelativeNS:      sig.RelativeNS,
			RiskLevel:       sig.RiskLevel,
			Summary:         sig.Summary,
			Title:           sig.Title,
			Evidence:        sig.Evidence,
			MountPoint:      sig.MountPoint,
		})
	}

	return
}
