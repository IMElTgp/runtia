#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/bin/runtia"
NAMESPACE="${RUNTIA_SMOKE_NAMESPACE:-runtia-smoke-$(date +%s)}"
POD="${RUNTIA_SMOKE_POD:-runtia-smoke-risk}"
IMAGE="${RUNTIA_SMOKE_IMAGE:-alpine:3.20}"
OUT_DIR="${RUNTIA_SMOKE_OUT_DIR:-$(mktemp -d -t runtia-k3s-smoke.XXXXXX)}"
RESULT_FILE="${RUNTIA_SMOKE_RESULT_FILE:-${OUT_DIR}/smoke-result.txt}"
KEEP="${RUNTIA_SMOKE_KEEP:-0}"
K3S="${RUNTIA_SMOKE_K3S:-k3s}"
CRICTL="${RUNTIA_SMOKE_CRICTL:-crictl}"
export RUNTIA_CRI_ENDPOINT="${RUNTIA_CRI_ENDPOINT:-unix:///run/k3s/containerd/containerd.sock}"
if [[ "${EUID}" -eq 0 ]]; then
	SUDO="${RUNTIA_SMOKE_SUDO:-}"
else
	SUDO="${RUNTIA_SMOKE_SUDO:-sudo}"
fi

mkdir -p "$(dirname "${RESULT_FILE}")"
: >"${RESULT_FILE}"

log_result() {
	printf '%s\n' "$*" | tee -a "${RESULT_FILE}"
}

cleanup() {
	if [[ "${KEEP}" != "1" ]]; then
		"${K3S}" kubectl delete namespace "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

on_error() {
	local exit_code=$?
	local line_no=${1:-unknown}
	log_result "status: fail"
	log_result "reason: command failed at line ${line_no} with exit code ${exit_code}"
	log_result "namespace: ${NAMESPACE}"
	log_result "pod: ${POD}"
	log_result "output: ${OUT_DIR}"
	log_result "result_file: ${RESULT_FILE}"
	log_result "runtia_log: ${OUT_DIR}/runtia.log"
	chmod 0755 "${OUT_DIR}" 2>/dev/null || true
	chmod 0644 "${OUT_DIR}"/* 2>/dev/null || true
	if [[ -f "${OUT_DIR}/runtia.log" ]]; then
		log_result "runtia_log_tail:"
		tail -n 120 "${OUT_DIR}/runtia.log" >>"${RESULT_FILE}" 2>/dev/null || true
	fi
	chmod 0644 "${RESULT_FILE}" 2>/dev/null || true
	exit "${exit_code}"
}
trap 'on_error ${LINENO}' ERR

fail() {
	log_result "status: fail"
	log_result "reason: $*"
	log_result "namespace: ${NAMESPACE}"
	log_result "pod: ${POD}"
	log_result "output: ${OUT_DIR}"
	log_result "result_file: ${RESULT_FILE}"
	exit 1
}

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		fail "missing required command: $1"
	fi
}

require_json_file() {
	local file="$1"
	if [[ ! -s "${OUT_DIR}/${file}" ]]; then
		fail "expected non-empty ${file} in ${OUT_DIR}"
	fi
	log_result "validated: ${file}"
}

require_json_category() {
	local file="$1"
	local category="$2"
	require_json_file "${file}"
	if ! grep -q "\"Category\": \"${category}\"" "${OUT_DIR}/${file}"; then
		fail "expected ${file} to contain finding category ${category}"
	fi
	local count
	count="$(grep -c "\"Category\": \"${category}\"" "${OUT_DIR}/${file}" || true)"
	log_result "validated: ${file} category=${category} findings=${count}"
}

log_result "status: running"
log_result "namespace: ${NAMESPACE}"
log_result "pod: ${POD}"
log_result "output: ${OUT_DIR}"
log_result "result_file: ${RESULT_FILE}"

require_command "${K3S}"
require_command "${CRICTL}"
if [[ -n "${SUDO}" ]]; then
	require_command "${SUDO}"
fi

cd "${ROOT_DIR}"
make build

"${K3S}" kubectl create namespace "${NAMESPACE}"
"${K3S}" kubectl apply -n "${NAMESPACE}" -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
  labels:
    app.kubernetes.io/name: runtia-smoke
spec:
  hostPID: true
  restartPolicy: Always
  containers:
    - name: tracer
      image: ${IMAGE}
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "sleep 3600"]
      securityContext:
        seccompProfile:
          type: Unconfined
        capabilities:
          add:
            - SYS_PTRACE
            - KILL
    - name: target
      image: ${IMAGE}
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "sleep 3600"]
EOF

"${K3S}" kubectl wait -n "${NAMESPACE}" --for=condition=Ready "pod/${POD}" --timeout=120s

pod_node="$("${K3S}" kubectl get pod -n "${NAMESPACE}" "${POD}" -o jsonpath='{.spec.nodeName}')"
local_node="$(hostname)"
if [[ -n "${pod_node}" && "${pod_node}" != "${local_node}" ]]; then
	fail "pod is scheduled on node ${pod_node}, but local node is ${local_node}; run on the scheduled node or constrain the Pod"
fi
log_result "validated: pod scheduled on local node ${local_node}"

mkdir -p "${OUT_DIR}"
(
	cd "${OUT_DIR}"
	if [[ -n "${SUDO}" ]]; then
		"${SUDO}" "${BIN}" --namespace "${NAMESPACE}" --pod "${POD}" >runtia.log 2>&1
	else
		"${BIN}" --namespace "${NAMESPACE}" --pod "${POD}" >runtia.log 2>&1
	fi
)
chmod 0755 "${OUT_DIR}" 2>/dev/null || true
chmod 0644 "${OUT_DIR}"/* 2>/dev/null || true
log_result "validated: runtia command completed"

require_json_category namespace.json namespace
require_json_category seccomp.json seccomp
require_json_category capabilities.json capabilities
require_json_category composition.json composition

if [[ -s "${OUT_DIR}/warnings.json" ]]; then
	log_result "validated: warnings.json"
else
	log_result "validated: warnings.json absent; no non-fatal warnings were emitted"
fi

log_result "status: pass"
chmod 0755 "${OUT_DIR}" 2>/dev/null || true
chmod 0644 "${OUT_DIR}"/* 2>/dev/null || true
chmod 0644 "${RESULT_FILE}" 2>/dev/null || true
