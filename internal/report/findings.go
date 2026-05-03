package report

import "github.com/IMElTgp/container-runtime-analysis/internal/model"

// findings.go converts signals to findings
// currently, composition is just a TODO
// just turn model.Signal into model.Finding

// if we take composition into consider, use a hash map to store different kinds of signals
// for hard-coded signal pairs, generate a composited signal and mark both of the signals in that pair as "covered"
// "covered" signals may still involve composition, but are not going to be turned into findings

func GenerateFindings(signals []*model.Signal) (findings []*model.Finding) {
	for _, sig := range signals {
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
