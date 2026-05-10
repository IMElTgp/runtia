package model

type Signal struct {
	// Signal combines Finding
	Finding
	// Covered means this primitive signal has been subsumed by a composition signal
	// and should not be emitted as a standalone finding.
	Covered bool
}
