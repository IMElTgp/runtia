package app

import (
	"fmt"
	"time"

	"github.com/IMElTgp/container-runtime-analysis/internal/analyze"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/report"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

type Config struct {
	ContainerID     string
	PID             int
	PrintToTerminal bool // whether to print to the terminal, default:true
	WriteJSON       bool // whether to generate JSON files, default:true
}

func (c *Config) run() error {
	if c.ContainerID == "" {
		return fmt.Errorf("failed to start: no valid container ID provided")
	}
	// target
	fmt.Println("===================================================")
	fmt.Println("Started resolving provided container ID...")
	fmt.Println("===================================================")
	fmt.Println()
	cgroupPath, err := target.ResolveCgroupPath(c.ContainerID)
	if err != nil {
		return err
	}
	// snapshot
	metadata := model.Metadata{
		CollectedAt: time.Now(),
		ContainerID: c.ContainerID,
		InitPID:     c.PID,
		CgroupPath:  cgroupPath,
	}
	fmt.Println("===================================================")
	fmt.Println("Started collection at", metadata.CollectedAt, "...")
	fmt.Println("===================================================")
	fmt.Println()
	snapshot, err := model.DoSnapshot(metadata)
	if err != nil {
		return err
	}
	// analyze
	r := &analyze.Rule{
		Snapshot: snapshot,
		Signals:  make([]model.Signal, 0),
	}
	fmt.Println("===================================================")
	fmt.Println("Started analyzing...")
	fmt.Println("===================================================")
	fmt.Println()
	r.Entry()
	// report
	findings := report.GenerateFindings(r.Signals)
	findings = report.SortFindings(findings)
	report.SortFindingsByCategory(findings)
	fmt.Println("===================================================")
	fmt.Println("Started outputting report...")
	fmt.Println("===================================================")
	fmt.Println()
	if c.PrintToTerminal {
		report.PrintToTerminal(findings)
	}
	if c.WriteJSON {
		if err := report.WriteFindingsAsJSON(report.CompositionFindings); err != nil {
			return err
		}
		if err := report.WriteFindingsAsJSON(report.CapabilitiesFindings); err != nil {
			return err
		}
		if err := report.WriteFindingsAsJSON(report.NamespaceFindings); err != nil {
			return err
		}
		if err := report.WriteFindingsAsJSON(report.MountFindings); err != nil {
			return err
		}
		if err := report.WriteFindingsAsJSON(report.SeccompFindings); err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) Run() error {
	return c.run()
}
