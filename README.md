# Runtia

Runtia is a Linux host-side CLI for inspecting the effective runtime security state of a running K3s Pod.

It does not scan images, manifests, RBAC, admission policy, or network policy. It inspects live workload containers from the node through Kubernetes metadata, CRI metadata, `/proc`, namespace references, mount information, seccomp state, and capability sets, then reports findings that weaken container or Pod isolation.

## K3s Pod-only MVP Status

Runtia currently targets a K3s Pod-only MVP.

Current MVP capabilities:

- resolve a running Pod from `--namespace` and `--pod`
- enumerate ordinary workload containers from `status.containerStatuses`
- skip init and ephemeral containers for the MVP
- resolve each container's main process PID with `crictl inspect -o json`
- collect live runtime facts from the host for each resolved container
- analyze namespace, seccomp, capability, and mount-related risk signals per container
- compose selected cross-container findings inside one Pod when runtime evidence proves a shared isolation boundary or shared volume backing source
- print a readable terminal summary with representative high-risk findings
- write per-category JSON reports and warning files for machine consumption

## Threat Model

Runtia focuses on runtime configuration that expands attack surface after an attacker can already execute code inside one Pod container or control one or more threads inside it.

The tool does not claim that an escape has already happened. It identifies runtime conditions that can make host impact, cross-container impact, or kernel attack-surface expansion more plausible.

## Runtime Pipeline

Runtia follows this pipeline:

```text
pod target -> container targets -> collect -> snapshot -> analyze -> pod composition -> report
```

1. resolve the Pod with `k3s kubectl get pod -n <namespace> <pod-name> -o json`
2. keep ordinary workload containers from the Pod status
3. resolve each container's main process PID with `crictl inspect -o json <runtime-container-id>`
4. resolve the container cgroup from the main PID
5. collect per-thread runtime facts from the host
6. analyze each container snapshot into structured findings
7. append Pod-level cross-container composition findings
8. render findings for terminal output and JSON output

## Input Model

Supported input:

- `--namespace <namespace>`
- `--pod <pod-name>`

The scanner is expected to run on the node where the target Pod is scheduled. The MVP does not scan arbitrary remote nodes.

## Output Model

Terminal output:

- warning messages for skipped best-effort steps
- overall finding counts by severity
- representative `Fatal` and `HighRisk` findings

JSON output:

- `capabilities.json`
- `composition.json`
- `mount.json`
- `namespace.json`
- `seccomp.json`
- `warnings.json`

Only categories with findings are written. `warnings.json` is written when best-effort resolution or collection steps had to skip a container or runtime fact.

## Build And Run

Recommended local install:

```bash
make install
```

If `~/.local/bin` is already in your `PATH`, run the scanner with `sudo`:

```bash
sudo runtia --namespace default --pod risk-pod
```

Direct build without installation:

```bash
make build
```

Run the local binary from the repository:

```bash
sudo ./bin/runtia --namespace default --pod risk-pod
```

## Environment Assumptions

- Linux K3s node
- target Pod is scheduled on the local node
- `sudo` or equivalent privileges for host `/proc` and cgroup inspection
- `k3s kubectl` is available
- `crictl` is available and can inspect the Pod's runtime container IDs
- host `/proc` and cgroup filesystems are mounted normally

Resolution and collection are best-effort. When a container ID, PID, cgroup, thread, namespace, or mount fact cannot be resolved after the configured wait/retry behavior, Runtia skips that item, prints a warning, and records the warning in `warnings.json`.

## What It Detects Today

The current analyzer focuses on four primitive categories:

- `namespace`: host namespace sharing, per-thread namespace deviation, and owner user namespace mismatch for non-user namespaces
- `seccomp`: disabled or suspicious seccomp state and `no_new_privs` disabled
- `capabilities`: dangerous capabilities in effective, permitted, ambient, inheritable, or bounding sets
- `mount`: non-private propagation, writable sensitive paths, and writable child mounts under read-only parents

Pod-level composition currently adds selected cross-container findings when evidence comes from at least two ordinary workload containers in the same Pod:

- shared PID namespace plus process-control capabilities
- shared PID namespace plus DAC capabilities for `/proc/$pid/root` exposure, when the MVP user namespace compatibility check passes
- shared volume writable producer plus sensitive consumer path

## Scope

Runtia is intentionally narrow.

It is not:

- an image vulnerability scanner
- an SBOM generator
- a Kubernetes admission controller
- a Kubernetes RBAC or ServiceAccount auditor
- a NetworkPolicy analyzer
- a full container security platform

It is a host-side runtime inspector focused on turning live low-level runtime facts into actionable findings.

## Real K3s Smoke Test

Run the real K3s smoke test on the node where the smoke Pod will be scheduled:

```bash
scripts/k3s_smoke.sh
```

If the current shell needs privileges for K3s and CRI access, run it from an interactive terminal where `sudo` can prompt:

```bash
RUNTIA_SMOKE_RESULT_FILE=/tmp/runtia-k3s-smoke-result.txt sudo -E scripts/k3s_smoke.sh
```

The script builds `./bin/runtia`, creates a temporary namespace, creates a two-container Pod with non-destructive detectable risk settings, runs:

```bash
sudo ./bin/runtia --namespace <namespace> --pod <pod-name>
```

It then verifies that `namespace.json`, `seccomp.json`, `capabilities.json`, and `composition.json` were written. `warnings.json` is optional and appears only when non-fatal warnings occur.

Useful overrides:

- `RUNTIA_SMOKE_NAMESPACE`: namespace to create and use
- `RUNTIA_SMOKE_POD`: Pod name
- `RUNTIA_SMOKE_IMAGE`: container image, default `alpine:3.20`
- `RUNTIA_SMOKE_OUT_DIR`: output directory for JSON reports
- `RUNTIA_SMOKE_RESULT_FILE`: result summary file to inspect after the run
- `RUNTIA_CRI_ENDPOINT`: CRI endpoint passed to `crictl`, default `unix:///run/k3s/containerd/containerd.sock`
- `RUNTIA_SMOKE_KEEP=1`: keep the namespace after the run for debugging

The smoke test validates detection and report generation only. It does not perform exploit proof.
