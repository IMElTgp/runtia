#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="${ROOT_DIR}/container-risk-lab/scripts/run-scenario-proof.sh"

SCENARIO="${SCENARIO:-}"
OUTPUT_FILE="${OUTPUT_FILE:-}"
KEEP_UP="${KEEP_UP:-0}"

usage() {
    cat <<'EOF'
Usage:
  ./run-proof.sh <scenario>
  SCENARIO=<scenario> ./run-proof.sh

Examples:
  ./run-proof.sh cap-sys-admin
  ./run-proof.sh cap-sys-admin-shared-mount
  ./run-proof.sh seccomp-unconfined
  OUTPUT_FILE=/tmp/proof.log ./run-proof.sh cap-kill-host-pidns
  KEEP_UP=1 ./run-proof.sh host-userns

Notes:
  - this wrapper always goes through container-risk-lab/scripts/run-scenario-proof.sh
  - the runner will prepare host assets first when needed, then start the scenario container, then run the proof against that exact container
  - the runner tears the environment down by default

Available scenarios:
EOF
    "${RUNNER}" --list
}

if [[ ! -x "${RUNNER}" ]]; then
    echo "Missing runner: ${RUNNER}" >&2
    exit 1
fi

if [[ $# -gt 0 ]]; then
    SCENARIO="$1"
    shift
fi

if [[ -z "${SCENARIO}" ]]; then
    usage
    exit 1
fi

cmd=("${RUNNER}" "--scenario" "${SCENARIO}")

if [[ -n "${OUTPUT_FILE}" ]]; then
    cmd+=("--output" "${OUTPUT_FILE}")
fi

if [[ "${KEEP_UP}" == "1" ]]; then
    cmd+=("--keep-up")
fi

exec "${cmd[@]}" "$@"
