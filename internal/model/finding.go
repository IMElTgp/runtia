package model

import "github.com/IMElTgp/container-runtime-analysis/internal/target"

type Finding struct {
	Category        string // "namespace", "seccomp", "capabilities", "mount"
	RiskLevel       int    // Fatal, HighRisk, MediumRisk, LowRisk, Info
	Title           string
	Summary         string
	Evidence        []string
	RelativeThreads []*target.Thread
	RelativeNS      *target.NSRef
	MountPoint      []string
	Recommendation  string
}
