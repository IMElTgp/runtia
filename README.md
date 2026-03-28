# Runtia

Runtia is a work-in-progress CLI for investigating the basic security-related runtime settings of a running container.

Instead of scanning an image or a deployment manifest, Runtia is meant to inspect what is actually in effect for a live container on a Linux host. The goal is to collect runtime facts, analyze them, and flag risky points that weaken container isolation.

## What The Tool Is Meant To Inspect

- namespaces, especially mount namespace (`mntns`) and user namespace (`userns`) behavior
- seccomp state and whether syscall filtering is missing or unexpectedly weak
- Linux capabilities and dangerous privileges retained by the container
- mount layout and other runtime details that can expand the attack surface
- host-visible process and container metadata needed to explain the findings

## What Kinds Of Risks It Should Recognize

- missing or weak user namespace isolation
- weak mount namespace separation
- seccomp disabled, absent, or less restrictive than expected
- overly broad capability sets
- risky mounts that expose sensitive host paths or enable unsafe write access

## Approach

Runtia is being designed around a simple inspection pipeline:

```text
target -> collect -> snapshot -> analyze -> finding -> report
```

1. resolve a scan target from a container ID or PID
2. collect raw runtime data from `/proc`, namespace references, mount information, and related kernel interfaces
3. normalize that data into a snapshot of the container's effective state
4. apply security rules to identify risky points
5. report structured findings in a readable form

## Current Status

This repository is under active development.

The direction is clear, but the scanner is not feature-complete yet. The current codebase is laying out the collection, analysis, and reporting structure needed for a host-side runtime security tool. Some packages are still placeholders while the core scan flow is being built out.

At this stage, Runtia should be understood as:

- a prototype for runtime container security inspection
- focused on Linux containers
- aimed at turning low-level runtime facts into actionable findings

## Scope

Runtia is focused on runtime inspection. It is not intended to be:

- an image vulnerability scanner
- an SBOM generator
- an admission controller
- a full orchestration or cluster security platform

## Environment Assumptions

- Linux host
- access to the target container's process information
- container runtime metadata available from the host

Docker-oriented target resolution is the first expected workflow, with room to expand later.

## Repository Layout

- `internal/target`: resolve what should be inspected
- `internal/collect`: gather raw runtime facts
- `internal/model`: shared structures for snapshots and findings
- `internal/analyze`: apply security rules and detect risky conditions
- `internal/report`: render findings for humans or machines

## Roadmap

- resolve targets from container IDs and PIDs
- collect namespace, seccomp, capability, and mount data from live containers
- define stable snapshot and finding models
- add initial detection rules for common container hardening gaps
- produce text and JSON reports
- expand runtime support beyond the initial Docker-based flow
