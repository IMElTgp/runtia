package analyze

import "github.com/IMElTgp/container-runtime-analysis/internal/model"

type Rule struct {
	Snapshot model.Snapshot
	Signals  []model.Signal
}

// threat levels
const (
	Safe = iota
	Info
	LowRisk
	MediumRisk
	HighRisk
	Fatal
)

func (r *Rule) Entry() {
	r.AnalyzeNamespaces()
	r.AnalyzeSeccomp()
	r.AnalyzeCapabilities()
	r.AnalyzeMount()
}
