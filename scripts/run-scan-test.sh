#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="${ROOT_DIR}/container-risk-lab"
SCENARIOS_DIR="${LAB_ROOT}/scenarios"
RUNTIA_BIN="${ROOT_DIR}/bin/runtia"
COMPOSE_FALLBACK_IMAGE="${COMPOSE_FALLBACK_IMAGE:-docker/compose:1.29.2}"
FALLBACK_REPO_MOUNT="/workspace/runtia"

declare -A PREPARE_SCRIPT
declare -A CLEANUP_SCRIPT

SCENARIO="${SCENARIO:-}"
KEEP_UP="${KEEP_UP:-0}"
OUTPUT_FILE="${OUTPUT_FILE:-}"
AUTO_BUILD="${AUTO_BUILD:-1}"

COMPOSE_CMD=()
COMPOSE_SCENARIOS_DIR="${SCENARIOS_DIR}"
COMPOSE_LAB_ROOT="${LAB_ROOT}"
TARGET_CONTAINER_NAME=""
PREPARED=0
STARTED=0

register_scenario() {
    local scenario="$1"
    local prepare_script="${2:-}"
    local cleanup_script="${3:-}"
    PREPARE_SCRIPT["${scenario}"]="${prepare_script}"
    CLEANUP_SCRIPT["${scenario}"]="${cleanup_script}"
}

register_scenario "baseline"
register_scenario "seccomp-unconfined"
register_scenario "cap-sys-admin"
register_scenario "host-userns" "prepare-host-userns.sh" "cleanup-host-userns.sh"
register_scenario "writable-host-mount" "prepare-writable-host-mount.sh" "cleanup-writable-host-mount.sh"
register_scenario "seccomp-unconfined-cap-sys-admin"
register_scenario "seccomp-unconfined-cap-mknod"
register_scenario "cap-kill-host-pidns" "prepare-cap-kill-host-pidns.sh" "cleanup-cap-kill-host-pidns.sh"
register_scenario "cap-sys-ptrace-host-pidns" "prepare-cap-sys-ptrace-host-pidns.sh" "cleanup-cap-sys-ptrace-host-pidns.sh"
register_scenario "cap-sys-admin-shared-mount" "prepare-shared-mount-host.sh" "cleanup-shared-mount-host.sh"
register_scenario "no-new-privs-delayed-cap" "prepare-no-new-privs-delayed-cap.sh" "cleanup-no-new-privs-delayed-cap.sh"
register_scenario "cap-sys-chroot-mountns" "prepare-cap-sys-chroot-mountns.sh" "cleanup-cap-sys-chroot-mountns.sh"
register_scenario "cap-dac-override-writable-host-mount" "prepare-dac-override-host-mount.sh" "cleanup-dac-override-host-mount.sh"

timestamp() {
    date '+%Y-%m-%d %H:%M:%S%z'
}

log() {
    printf '[%s] %s\n' "$(timestamp)" "$*"
}

section() {
    printf '\n=== %s ===\n' "$*"
}

usage() {
    cat <<'EOF'
Usage:
  ./run-scan-test.sh <scenario>
  SCENARIO=<scenario> ./run-scan-test.sh
  ./run-scan-test.sh --list

Environment variables:
  OUTPUT_FILE=/tmp/scan.log
  KEEP_UP=1
  AUTO_BUILD=0
EOF
}

list_scenarios() {
    local scenario
    for scenario in "${!PREPARE_SCRIPT[@]}"; do
        printf '%s\n' "${scenario}"
    done | sort
}

parse_args() {
    while (($# > 0)); do
        case "$1" in
            --list)
                list_scenarios
                exit 0
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                if [[ -z "${SCENARIO}" ]]; then
                    SCENARIO="$1"
                    shift
                else
                    echo "Unexpected argument: $1" >&2
                    exit 1
                fi
                ;;
        esac
    done
}

setup_output() {
    if [[ -n "${OUTPUT_FILE}" ]]; then
        mkdir -p "$(dirname -- "${OUTPUT_FILE}")"
        : > "${OUTPUT_FILE}"
        exec > >(tee -a "${OUTPUT_FILE}") 2>&1
    fi
}

resolve_compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD=(docker compose)
        return
    fi

    if command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD=(docker-compose)
        return
    fi

    mkdir -p /tmp/container-risk-labs
    COMPOSE_LAB_ROOT="${FALLBACK_REPO_MOUNT}/container-risk-lab"
    COMPOSE_SCENARIOS_DIR="${COMPOSE_LAB_ROOT}/scenarios"
    COMPOSE_CMD=(
        docker run --rm
        --user 0:0
        --security-opt label=disable
        -v /var/run/docker.sock:/var/run/docker.sock
        -v /tmp/container-risk-labs:/tmp/container-risk-labs
        -v "${ROOT_DIR}:${FALLBACK_REPO_MOUNT}:ro"
        -w "${COMPOSE_LAB_ROOT}"
        "${COMPOSE_FALLBACK_IMAGE}"
    )
}

scenario_compose_file() {
    local scenario="$1"
    printf '%s\n' "${COMPOSE_SCENARIOS_DIR}/${scenario}/docker-compose.yml"
}

ensure_supported_scenario() {
    [[ -n "${SCENARIO}" ]] || { usage >&2; exit 1; }
    [[ -v PREPARE_SCRIPT["${SCENARIO}"] ]] || { echo "Unsupported scenario: ${SCENARIO}" >&2; exit 1; }
    [[ -f "${SCENARIOS_DIR}/${SCENARIO}/docker-compose.yml" ]] || { echo "Missing compose file for ${SCENARIO}" >&2; exit 1; }
}

build_runtia_if_needed() {
    if [[ "${AUTO_BUILD}" != "1" ]]; then
        [[ -x "${RUNTIA_BIN}" ]] || { echo "Missing executable runtia binary: ${RUNTIA_BIN}" >&2; exit 1; }
        return
    fi

    section "Build Runtia"
    log "go build -o ${RUNTIA_BIN} ./cmd/main.go"
    (cd "${ROOT_DIR}" && go build -o "${RUNTIA_BIN}" ./cmd/main.go)
}

run_script_file() {
    local script_name="$1"
    [[ -n "${script_name}" ]] || return 0
    local script_path="${LAB_ROOT}/scripts/${script_name}"
    [[ -x "${script_path}" ]] || { echo "Script is not executable: ${script_path}" >&2; exit 1; }
    log "running script: ${script_path}"
    "${script_path}"
}

compose_down() {
    local compose_file
    compose_file="$(scenario_compose_file "${SCENARIO}")"
    log "docker compose down for scenario=${SCENARIO}"
    "${COMPOSE_CMD[@]}" -f "${compose_file}" down --remove-orphans
}

compose_up() {
    local compose_file
    compose_file="$(scenario_compose_file "${SCENARIO}")"
    log "docker compose up for scenario=${SCENARIO}"
    "${COMPOSE_CMD[@]}" -f "${compose_file}" up -d --build
}

resolve_container_name() {
    local compose_file
    compose_file="$(scenario_compose_file "${SCENARIO}")"
    local -a container_ids=()
    mapfile -t container_ids < <("${COMPOSE_CMD[@]}" -f "${compose_file}" ps -q)
    if [[ "${#container_ids[@]}" -ne 1 ]]; then
        echo "Expected exactly one container for scenario ${SCENARIO}, got ${#container_ids[@]}" >&2
        exit 1
    fi
    local container_id="${container_ids[0]}"
    local actual_scenario
    actual_scenario="$(docker inspect -f '{{ index .Config.Labels "container-risk-labs.scenario" }}' "${container_id}")"
    [[ "${actual_scenario}" == "${SCENARIO}" ]] || {
        echo "Container ${container_id} belongs to scenario ${actual_scenario}, expected ${SCENARIO}" >&2
        exit 1
    }
    docker inspect -f '{{.Name}}' "${container_id}" | sed 's#^/##'
}

cleanup() {
    if [[ "${KEEP_UP}" == "1" ]]; then
        section "Cleanup"
        log "Skipping cleanup because KEEP_UP=1"
        return
    fi

    if (( STARTED == 1 )); then
        section "Compose down"
        compose_down || true
    fi

    if (( PREPARED == 1 )); then
        local cleanup_script="${CLEANUP_SCRIPT[${SCENARIO}]:-}"
        if [[ -n "${cleanup_script}" ]]; then
            section "Cleanup"
            run_script_file "${cleanup_script}" || true
        fi
    fi
}

on_exit() {
    local exit_code=$?
    cleanup
    section "Result"
    printf 'scenario=%s\n' "${SCENARIO:-<unset>}"
    printf 'container=%s\n' "${TARGET_CONTAINER_NAME:-<unset>}"
    if (( exit_code == 0 )); then
        printf 'status=success\n'
    else
        printf 'status=failed\n'
        printf 'exit_code=%d\n' "${exit_code}"
    fi
}

main() {
    parse_args "$@"
    setup_output
    resolve_compose_cmd
    ensure_supported_scenario
    build_runtia_if_needed
    trap on_exit EXIT

    section "Run Metadata"
    printf 'scenario=%s\n' "${SCENARIO}"
    printf 'compose_impl=%s\n' "${COMPOSE_CMD[*]}"
    printf 'keep_up=%s\n' "${KEEP_UP}"
    printf 'auto_build=%s\n' "${AUTO_BUILD}"
    if [[ -n "${OUTPUT_FILE}" ]]; then
        printf 'output_file=%s\n' "${OUTPUT_FILE}"
    fi

    section "Reset Old Containers"
    compose_down

    local prepare_script="${PREPARE_SCRIPT[${SCENARIO}]:-}"
    if [[ -n "${prepare_script}" ]]; then
        section "Prepare"
        run_script_file "${prepare_script}"
        PREPARED=1
    fi

    section "Start Containers"
    compose_up
    STARTED=1

    section "Resolve Container"
    TARGET_CONTAINER_NAME="$(resolve_container_name)"
    printf 'container=%s\n' "${TARGET_CONTAINER_NAME}"

    section "Run Runtia"
    "${RUNTIA_BIN}" --container-id "${TARGET_CONTAINER_NAME}"
}

main "$@"
