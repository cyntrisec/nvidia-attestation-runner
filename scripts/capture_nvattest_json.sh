#!/usr/bin/env bash
# Capture NVIDIA nvattest JSON evidence with the Rust wrapper.
#
# This script assumes the host already has a supported NVIDIA driver, a GPU in
# confidential-computing mode, and `nvattest` on PATH. It intentionally does not
# install drivers, mutate GPU state, or launch cloud infrastructure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

BACKEND="local"
OUT_DIR=""
NONCE_HEX=""
RUNNER_BIN=""
ALLOW_POLICY_FAILURE=false

usage() {
    cat <<'USAGE'
Usage:
  scripts/capture_nvattest_json.sh [options]

Options:
  --backend local|remote|both
      Which nvattest verifier path to capture. Default: local.

  --out-dir DIR
      Output directory. Default: artifacts/nvattest-YYYYmmddTHHMMSSZ.

  --nonce HEX
      32-byte nonce encoded as 64 hex characters. Default: generated locally.

  --runner PATH
      Path to a built nvidia-attestation-runner binary. Default: use cargo run.

  --allow-policy-failure
      Preserve bundles even when policy rejects. This is useful for negative
      fixtures. With this flag the runner exits 0 on a policy rejection, so the
      .status file holds 0 as well. Read the verdict from "policy.accepted" in
      the bundle or "status" in the summary, not from the exit status.

  -h, --help
      Show this help.

Outputs:
  nonce.txt
  metadata/*.txt
  nvattest-local.bundle.json / nvattest-remote.bundle.json
  nvattest-local.summary.json / nvattest-remote.summary.json
  nvattest-local.stderr.txt  / nvattest-remote.stderr.txt
  nvattest-local.status      / nvattest-remote.status
  SHA256SUMS

Do not commit raw output without reviewing and redacting cloud account IDs,
hostnames, serial numbers, GPU UUIDs, or other environment-specific values.
USAGE
}

die() {
    echo "error: $*" >&2
    exit 1
}

log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --backend) BACKEND="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --nonce) NONCE_HEX="$2"; shift 2 ;;
        --runner) RUNNER_BIN="$2"; shift 2 ;;
        --allow-policy-failure) ALLOW_POLICY_FAILURE=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "${BACKEND}" in
    local|remote|both) ;;
    *) die "--backend must be local, remote, or both" ;;
esac

if [[ -z "${NONCE_HEX}" ]]; then
    NONCE_HEX="$(openssl rand -hex 32)"
fi
if [[ ! "${NONCE_HEX}" =~ ^[[:xdigit:]]{64}$ ]]; then
    die "--nonce must be 32 bytes encoded as 64 hex characters"
fi

if [[ -z "${OUT_DIR}" ]]; then
    OUT_DIR="${REPO_DIR}/artifacts/nvattest-$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "${OUT_DIR}/metadata"

if ! command -v nvattest >/dev/null 2>&1; then
    die "nvattest not found on PATH"
fi
if [[ -n "${RUNNER_BIN}" && ! -x "${RUNNER_BIN}" ]]; then
    die "--runner path is not executable: ${RUNNER_BIN}"
fi

printf '%s\n' "${NONCE_HEX}" > "${OUT_DIR}/nonce.txt"
date -u +%Y-%m-%dT%H:%M:%SZ > "${OUT_DIR}/metadata/captured_at.txt"
uname -a > "${OUT_DIR}/metadata/uname.txt" 2>&1 || true
command -v nvattest > "${OUT_DIR}/metadata/nvattest_path.txt" 2>&1 || true
# `nvattest version` is the supported form in nvattest 1.2.2 and 2.0.0; both
# reject `--version`. The flag is kept only as a fallback for other builds.
if ! nvattest version > "${OUT_DIR}/metadata/nvattest_version.txt" 2>&1; then
    nvattest --version > "${OUT_DIR}/metadata/nvattest_version.txt" 2>&1 || true
fi
nvidia-smi > "${OUT_DIR}/metadata/nvidia_smi.txt" 2>&1 || true
nvidia-smi --query-gpu=name,uuid,driver_version,vbios_version,pci.bus_id,compute_cap --format=csv \
    > "${OUT_DIR}/metadata/nvidia_smi_query.csv" 2>&1 || true
nvidia-smi conf-compute -f > "${OUT_DIR}/metadata/conf_compute_f.txt" 2>&1 || true
nvidia-smi conf-compute -grs > "${OUT_DIR}/metadata/conf_compute_get_ready.txt" 2>&1 || true

runner_cmd() {
    if [[ -n "${RUNNER_BIN}" ]]; then
        "${RUNNER_BIN}" "$@"
    else
        cargo run --quiet --manifest-path "${REPO_DIR}/Cargo.toml" -- "$@"
    fi
}

capture_backend() {
    local name="$1"
    local runner_backend="$2"
    local stdout_path="${OUT_DIR}/nvattest-${name}.bundle.json"
    local summary_path="${OUT_DIR}/nvattest-${name}.summary.json"
    local stderr_path="${OUT_DIR}/nvattest-${name}.stderr.txt"
    local status_path="${OUT_DIR}/nvattest-${name}.status"
    local args=(
        --backend "${runner_backend}"
        --nonce "${NONCE_HEX}"
        --pretty
        --summary-file "${summary_path}"
    )
    if ${ALLOW_POLICY_FAILURE}; then
        args+=(--allow-policy-failure)
    fi

    log "Capturing nvattest ${name} verifier evidence."
    set +e
    runner_cmd "${args[@]}" > "${stdout_path}" 2> "${stderr_path}"
    local status=$?
    set -e
    printf '%s\n' "${status}" > "${status_path}"
    log "nvattest ${name} capture exit status: ${status}"
}

case "${BACKEND}" in
    local)
        capture_backend local nvattest-local-json
        ;;
    remote)
        capture_backend remote nvattest-remote-json
        ;;
    both)
        capture_backend local nvattest-local-json
        capture_backend remote nvattest-remote-json
        ;;
esac

cat > "${OUT_DIR}/README.txt" <<'EOF'
This directory was produced by scripts/capture_nvattest_json.sh.

Review and redact before committing any raw evidence. The bundle JSON preserves
the NVIDIA verifier output under bundle.report.raw and may contain GPU UUIDs,
driver/VBIOS versions, host-specific metadata, or cloud-environment identifiers.

The summary JSON is the redacted integration artifact intended for AIR platform
evidence and SIEM export. It contains policy status and evidence hashes, not raw
NVIDIA tokens or verifier transcripts.
EOF

(cd "${OUT_DIR}" && find . -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
log "Wrote ${OUT_DIR}"
