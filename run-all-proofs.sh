#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="${ROOT_DIR}/container-risk-lab/scripts/run-scenario-proof.sh"

OUTPUT_DIR="${OUTPUT_DIR:-/tmp/container-risk-labs/proof-runs/all-$(date '+%Y%m%d-%H%M%S')}"
STOP_ON_ERROR="${STOP_ON_ERROR:-0}"

timestamp() {
    date '+%Y-%m-%d %H:%M:%S%z'
}

usage() {
    cat <<'EOF'
Usage:
  ./run-all-proofs.sh

Environment variables:
  OUTPUT_DIR=/tmp/my-proof-runs
  STOP_ON_ERROR=1

Behavior:
  - runs every scenario currently wired into the automated proof runner
  - writes one log file per scenario under OUTPUT_DIR
  - writes a plain-text summary and a markdown summary under OUTPUT_DIR
  - continues after failures by default; set STOP_ON_ERROR=1 to stop on first failure
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

if [[ ! -x "${RUNNER}" ]]; then
    echo "Missing runner: ${RUNNER}" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

SUMMARY_TSV="${OUTPUT_DIR}/summary.tsv"
SUMMARY_MD="${OUTPUT_DIR}/summary.md"

printf 'scenario\tstatus\tlog_file\n' > "${SUMMARY_TSV}"
cat > "${SUMMARY_MD}" <<EOF
# Proof Run Summary

- started_at: $(timestamp)
- output_dir: ${OUTPUT_DIR}

| scenario | status | log file |
|---|---|---|
EOF

mapfile -t SCENARIOS < <("${RUNNER}" --list)

total=0
passed=0
failed=0

for scenario in "${SCENARIOS[@]}"; do
    [[ -n "${scenario}" ]] || continue
    total=$((total + 1))

    log_file="${OUTPUT_DIR}/${scenario}.log"
    echo "[$(timestamp)] running ${scenario}"

    if OUTPUT_FILE="${log_file}" "${RUNNER}" --scenario "${scenario}"; then
        status="success"
        passed=$((passed + 1))
    else
        status="failed"
        failed=$((failed + 1))
    fi

    printf '%s\t%s\t%s\n' "${scenario}" "${status}" "${log_file}" >> "${SUMMARY_TSV}"
    printf '| `%s` | `%s` | `%s` |\n' "${scenario}" "${status}" "${log_file}" >> "${SUMMARY_MD}"

    if [[ "${status}" == "failed" && "${STOP_ON_ERROR}" == "1" ]]; then
        echo "[$(timestamp)] stopping early because STOP_ON_ERROR=1"
        break
    fi
done

cat >> "${SUMMARY_MD}" <<EOF

- finished_at: $(timestamp)
- total: ${total}
- passed: ${passed}
- failed: ${failed}
EOF

echo
echo "All logs: ${OUTPUT_DIR}"
echo "Summary TSV: ${SUMMARY_TSV}"
echo "Summary MD: ${SUMMARY_MD}"
echo "Total=${total} Passed=${passed} Failed=${failed}"

if (( failed > 0 )); then
    exit 1
fi
