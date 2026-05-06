# Runtia

Runtia is a Linux host-side CLI for inspecting the effective runtime security state of a running Docker container.

It does not scan images or manifests. It inspects the live container from the host through `/proc`, namespace references, mount information, seccomp state, and capability sets, then reports findings that weaken container isolation.

## MVP Status

Runtia has reached a usable MVP stage.

Current MVP capabilities:

- resolve a running Docker container from `--container-id`
- collect live runtime facts from the host
- analyze namespace, seccomp, capability, and mount-related risk signals
- print a readable terminal summary with representative high-risk findings
- write per-category JSON reports for machine consumption

The current implementation has already been verified against:

- a low-risk baseline container
- a container with `seccomp=unconfined`
- a container with `CAP_SYS_ADMIN`

## What It Detects Today

The current analyzer focuses on four categories:

- `namespace`
  - host user namespace sharing
  - host PID namespace sharing
  - host mount namespace sharing
  - per-thread namespace deviation from the main thread
  - owner user namespace mismatch for non-user namespaces

- `seccomp`
  - seccomp fully disabled
  - strict seccomp mode
  - filter mode without attached filters
  - `no_new_privs` disabled

- `capabilities`
  - dangerous capabilities in effective, permitted, ambient, inheritable, or bounding sets
  - risk prioritization for capabilities such as `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, `CAP_NET_ADMIN`, `CAP_BPF`, and others

- `mount`
  - non-private mount propagation markers such as `shared:X`
  - writable sensitive runtime or host-visible paths
  - writable child mount under a read-only parent mount

## Runtime Pipeline

Runtia follows this pipeline:

```text
target -> collect -> snapshot -> analyze -> finding -> report
```

1. resolve a scan target from a Docker container ID
2. collect raw runtime facts from the host
3. normalize them into a snapshot
4. analyze the snapshot into structured findings
5. render findings for terminal output and JSON output

## Current Input Model

Current supported input:

- Docker container ID via `--container-id`

Not yet wired as a supported user-facing path:

- direct PID-based scanning

## Output Model

Terminal output:

- overall finding counts by severity
- representative `Fatal` and `HighRisk` findings

JSON output:

- `capabilities.json`
- `mount.json`
- `namespace.json`
- `seccomp.json`

Only categories with findings are written.

## Build And Run

Build:

```bash
go build -o ./bin/runtia ./cmd
```

Run against a live Docker container:

```bash
./bin/runtia --container-id <container-id>
```

Example:

```bash
docker run -d --rm --name runtia-demo --security-opt seccomp=unconfined alpine sleep 600
./bin/runtia --container-id runtia-demo
docker rm -f runtia-demo
```

## Environment Assumptions

- Linux host
- Docker Engine
- host access to the target container's `/proc` information

This tool is currently oriented around rootful Docker-on-Linux style inspection.

## Repository Layout

- `cmd`
  - CLI entrypoint
- `internal/app`
  - orchestration for one scan run
- `internal/target`
  - resolve scan targets and enumerate container threads
- `internal/collect`
  - collect raw runtime facts from the host
- `internal/model`
  - shared snapshot, signal, and finding structures
- `internal/analyze`
  - risk analysis rules
- `internal/report`
  - terminal and JSON reporting

## Scope

Runtia is intentionally narrow.

It is not:

- an image vulnerability scanner
- an SBOM generator
- a Kubernetes admission controller
- a full container security platform

It is a host-side runtime inspector focused on turning live low-level runtime facts into actionable findings.

## Verified Lab

The repository currently includes or references a local runtime risk lab under `./container-risk-lab`.

The following scenarios are already suitable for the current MVP:

- `baseline`
- `seccomp-unconfined`
- `cap-sys-admin`

Additional scenarios such as host PID namespace sharing and mount-related edge cases are appropriate next-step validation targets as the runtime coverage is expanded further.

## Next Steps

The MVP is in place. The next work is additive rather than foundational:

- expand live validation coverage to more namespace and mount scenarios
- improve the PID-based target path
- refine reporting ergonomics and JSON schema
- tighten error handling and integration tests
