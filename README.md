# Runtia

Runtia is a Linux host-side CLI for inspecting the effective runtime security state of a running Docker container.

It does not scan images or manifests. It inspects the live container from the host through `/proc`, namespace references, mount information, seccomp state, and capability sets, then reports findings that weaken container isolation.

## Threat Model

Runtia focuses on runtime configuration that expands the attack surface of a container after an attacker can already execute code inside it or control one or more threads inside it.

It does not assume the attacker always has container-root privileges, and it does not try to judge how the attacker entered the container in the first place.

The tool does not claim that a container escape has already happened. It identifies runtime conditions that can make host impact, cross-container impact, or kernel attack-surface expansion more plausible.

## MVP Status

Runtia has reached a usable MVP stage.

Current MVP capabilities:

- resolve a running Docker container from `--container-id`
- collect live runtime facts from the host
- analyze namespace, seccomp, capability, and mount-related risk signals
- compose multiple weaker or contextual signals into higher-level hard-coded composition findings
- print a readable terminal summary with representative high-risk findings
- write per-category JSON reports for machine consumption

The current implementation has already been verified against:

- a low-risk baseline container
- a container with `seccomp=unconfined`
- a container with `CAP_SYS_ADMIN`

## Why Thread-Level Analysis

Container runtimes usually assign namespace, seccomp, capability, and mount-related state when the container starts, but the kernel ultimately enforces much of that state on a per-thread execution path.

Later `execve`, capability transitions, ambient capabilities, `setns`, seccomp filter tree differences, or synchronization failures can produce thread-level differences at runtime. Runtia therefore treats threads as the smallest analysis unit while still using container-level context as background.

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
- `composition.json`
- `mount.json`
- `namespace.json`
- `seccomp.json`

Only categories with findings are written. When no rule matches, Runtia emits no finding for that category.

## Build And Run

Recommended local install:

```bash
make install
```

If `~/.local/bin` is already in your `PATH`, you can then run:

```bash
runtia --container-id <container-id>
```

Direct build without installation:

```bash
make build
```

Run the local binary from the repository:

```bash
./bin/runtia --container-id <container-id>
```

Example:

```bash
docker run -d --rm --name runtia-demo --security-opt seccomp=unconfined alpine sleep 600
runtia --container-id runtia-demo
docker rm -f runtia-demo
```

## Environment Assumptions

- Linux host
- Docker Engine
- host access to the target container's `/proc` information

This tool is currently oriented around rootful Docker-on-Linux style inspection.

When direct non-root access to `/proc/<pid>/task/<tid>/ns/*` is denied, Runtia can fall back to a privileged Docker helper container to recover namespace identity for analysis. The helper image defaults to `alpine:latest` and can be overridden with `RUNTIA_NAMESPACE_HELPER_IMAGE`.

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

Representative validated scenarios now include:

- single-rule:
  - `baseline`
  - `seccomp-unconfined`
  - `cap-sys-admin`
  - `cap-net-admin`
  - `cap-bpf`
  - `cap-sys-module`
  - `cap-sys-rawio`
  - `cap-sys-boot`
  - `cap-net-raw`
  - `cap-mknod`
  - `cap-perfmon`
  - `cap-setfcap`
  - `cap-setpcap`
  - `cap-sys-resource`
  - `cap-dac-read-search`
  - `cap-dac-override-single`
  - `host-pidns`
  - `host-userns`
  - `shared-mount`
  - `writable-host-mount`
- composition:
  - `seccomp-unconfined-cap-sys-admin`
  - `seccomp-unconfined-cap-mknod`
  - `cap-kill-host-pidns`
  - `cap-sys-ptrace-host-pidns`
  - `cap-sys-admin-shared-mount`
  - `no-new-privs-delayed-cap`
  - `cap-sys-chroot-mountns`

Current validation status is intentionally split into three buckets:

- detection verified and exploit/state validation successful
- detection verified but the chosen exploit probe is blocked by host hardening
- still pending on another environment

For example, `cap-dac-override-writable-host-mount` now detects the dangerous combination correctly, but direct host-file write probes can still be blocked on hardened hosts by SELinux or other LSM and labeling controls.

## Current Limits

Most remaining gaps are not implementation omissions. They are environment-limited:

- a few `HighRisk` capabilities would require touching host-global state to prove directly on this machine
- some rules lack a meaningful local test surface on this host
- some proof paths do not produce a clean, reversible, container-local signal under the current kernel/runtime combination

Examples include `CAP_SYS_TIME`, `CAP_AUDIT_CONTROL`, `CAP_MAC_OVERRIDE`, `CAP_MAC_ADMIN`, and `CAP_CHECKPOINT_RESTORE`.
