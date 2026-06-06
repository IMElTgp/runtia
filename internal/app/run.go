package app

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/IMElTgp/container-runtime-analysis/internal/analyze"
	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/report"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

type Config struct {
	Namespace       string
	PodName         string
	NodeName        string
	PrintToTerminal bool // whether to print to the terminal, default:true
	WriteJSON       bool // whether to generate JSON files, default:true

	Findings          []*model.Finding
	Warnings          []model.Warning
	ScannedContainers int
	SkippedContainers int
}

var (
	resolvePod = target.ResolvePod
	sleep      = time.Sleep
	hostname   = os.Hostname

	resolveContainerPID    = target.ResolveContainerPIDByCRICTL
	resolveCgroupPathByPID = target.ResolveCgroupPathByPID
	resetCollectorState    = collect.ResetState
	doSnapshot             = model.DoSnapshot
	now                    = time.Now

	analyzeSnapshot = func(snapshot model.Snapshot) []model.Signal {
		r := &analyze.Rule{
			Snapshot: snapshot,
			Signals:  make([]model.Signal, 0),
		}
		r.Entry()
		return r.Signals
	}
	composePodFindings = analyze.ComposePodFindings

	printFindings = func(findings []*model.Finding) {
		report.PrintToTerminal(findings)
	}

	printSummary = func(config Config) {
		fmt.Println("Pod Scan Summary:")
		fmt.Println(" Namespace:", config.Namespace)
		fmt.Println(" Pod:", config.PodName)
		if config.NodeName != "" {
			fmt.Println(" Node:", config.NodeName)
		}
		fmt.Println(" Scanned Containers:", config.ScannedContainers)
		fmt.Println(" Skipped Containers:", config.SkippedContainers)
		fmt.Println(" Warnings:", len(config.Warnings))
		if len(config.Warnings) > 0 {
			fmt.Println(" See warnings.json for non-fatal scan warnings.")
		}
		fmt.Println()
	}

	writeFindings = func(findings []*model.Finding) error {
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
		return report.WriteFindingsAsJSON(report.SeccompFindings)
	}

	writeWarnings = report.WriteWarningsAsJSON
)

func (c *Config) run() error {
	if strings.TrimSpace(c.Namespace) == "" {
		return fmt.Errorf("failed to start: namespace is required")
	}
	if strings.TrimSpace(c.PodName) == "" {
		return fmt.Errorf("failed to start: pod name is required")
	}

	c.Findings = nil
	c.Warnings = nil
	c.ScannedContainers = 0
	c.SkippedContainers = 0
	c.NodeName = ""

	fmt.Println("===================================================")
	fmt.Println("Started resolving provided pod...")
	fmt.Println("===================================================")
	fmt.Println()

	pod, err := resolvePod(c.Namespace, c.PodName)
	if err != nil {
		return err
	}
	if podHasMissingContainerID(pod) {
		sleep(time.Second)
		pod, err = resolvePod(c.Namespace, c.PodName)
		if err != nil {
			return err
		}
	}

	if err := validatePodNode(pod); err != nil {
		return err
	}
	c.NodeName = pod.NodeName

	analyses := make([]analyze.PodContainerAnalysis, 0, len(pod.Containers))
	for _, container := range pod.Containers {
		analysis, ok := c.scanContainer(pod, container)
		if !ok {
			continue
		}
		analyses = append(analyses, analysis)
		c.Findings = append(c.Findings, analysis.Findings...)
		c.ScannedContainers++
	}

	if c.ScannedContainers == 0 {
		if c.WriteJSON && len(c.Warnings) > 0 {
			if err := writeWarnings(c.Warnings); err != nil {
				return err
			}
		}
		return fmt.Errorf("no containers were scanned successfully for pod %s/%s", pod.Namespace, pod.Name)
	}

	c.Findings = append(c.Findings, composePodFindings(analyses)...)
	c.Findings = report.SortFindings(c.Findings)
	report.SortFindingsByCategory(c.Findings)

	fmt.Println("===================================================")
	fmt.Println("Started outputting report...")
	fmt.Println("===================================================")
	fmt.Println()

	if c.PrintToTerminal {
		printSummary(*c)
		printFindings(c.Findings)
	}
	if c.WriteJSON {
		if err := writeFindings(c.Findings); err != nil {
			return err
		}
		if err := writeWarnings(c.Warnings); err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) scanContainer(pod target.PodTarget, container target.ContainerTarget) (analyze.PodContainerAnalysis, bool) {
	if strings.TrimSpace(container.ContainerID) == "" {
		c.warn(pod, container, "resolve", "container has no containerID after one retry; skipped")
		c.SkippedContainers++
		return analyze.PodContainerAnalysis{}, false
	}

	runtimeID := container.RuntimeID
	if runtimeID == "" {
		runtimeID = container.ContainerID
	}

	pid, err := resolveContainerPID(runtimeID)
	if err != nil {
		c.warn(pod, container, "resolve-pid", err.Error())
		c.SkippedContainers++
		return analyze.PodContainerAnalysis{}, false
	}

	cgroupPath, err := resolveCgroupPathByPID(pid)
	if err != nil {
		c.warn(pod, container, "resolve-cgroup", err.Error())
		c.SkippedContainers++
		return analyze.PodContainerAnalysis{}, false
	}

	resetCollectorState()

	metadata := model.Metadata{
		CollectedAt:   now(),
		Namespace:     pod.Namespace,
		PodName:       pod.Name,
		NodeName:      pod.NodeName,
		ContainerName: container.Name,
		ContainerID:   container.ContainerID,
		Runtime:       container.Runtime,
		RuntimeID:     container.RuntimeID,
		InitPID:       pid,
		CgroupPath:    cgroupPath,
	}

	fmt.Println("===================================================")
	fmt.Println("Started collection at", metadata.CollectedAt, "for container", container.Name, "...")
	fmt.Println("===================================================")
	fmt.Println()

	snapshot, err := doSnapshot(metadata)
	if err != nil {
		c.warn(pod, container, "collect", err.Error())
		c.SkippedContainers++
		return analyze.PodContainerAnalysis{}, false
	}
	for _, warning := range snapshot.Warnings {
		c.warn(pod, container, "collect", warning)
	}

	fmt.Println("===================================================")
	fmt.Println("Started analyzing container", container.Name, "...")
	fmt.Println("===================================================")
	fmt.Println()

	signals := analyzeSnapshot(snapshot)
	findings := report.GenerateFindings(signals)
	model.AttachSnapshotContextToFindings(findings, snapshot)
	return analyze.PodContainerAnalysis{Snapshot: snapshot, Signals: signals, Findings: findings}, true
}

func (c *Config) warn(pod target.PodTarget, container target.ContainerTarget, stage, message string) {
	c.Warnings = append(c.Warnings, model.Warning{
		Namespace:     pod.Namespace,
		PodName:       pod.Name,
		NodeName:      pod.NodeName,
		ContainerName: container.Name,
		ContainerID:   container.ContainerID,
		Stage:         stage,
		Message:       message,
	})
}

func podHasMissingContainerID(pod target.PodTarget) bool {
	for _, container := range pod.Containers {
		if strings.TrimSpace(container.ContainerID) == "" {
			return true
		}
	}
	return false
}

func validatePodNode(pod target.PodTarget) error {
	if strings.TrimSpace(pod.NodeName) == "" {
		return nil
	}
	localHost, err := hostname()
	if err != nil {
		return fmt.Errorf("get local hostname failed: %w", err)
	}
	if strings.TrimSpace(localHost) != pod.NodeName {
		return fmt.Errorf("pod %s/%s is scheduled on node %s, but local node is %s", pod.Namespace, pod.Name, pod.NodeName, localHost)
	}
	return nil
}

func (c *Config) Run() error {
	return c.run()
}
