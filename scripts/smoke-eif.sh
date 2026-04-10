#!/usr/bin/env bash

# smoke-eif.sh runs smoke tests against a real Nitro Enclave EIF.
# Requires a 2xlarge-nitro runner (nitro-cli + /dev/nitro_enclaves available).
#
# Usage:
#   EIF_PATH=./enclave.eif scripts/smoke-eif.sh
#
# Environment variables:
#   EIF_PATH         Path to the enclave.eif file (required)
#   ENCLAVE_CID      VSOCK CID for the enclave (default: 16)
#   ENCLAVE_CPU      CPU count for the enclave (default: 2)
#   ENCLAVE_MEMORY   Memory in MiB for the enclave (default: 4096)
set -eux

export PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export BIN_DIR="${PROJECT_DIR}/bin"

: "${EIF_PATH:?EIF_PATH must be set to the path of the enclave.eif file}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
ENCLAVE_CPU="${ENCLAVE_CPU:-2}"
ENCLAVE_MEMORY="${ENCLAVE_MEMORY:-4096}"

APP_PID=""
ENCLAVE_ID=""

cleanup() {
    if [ -n "$APP_PID" ] && kill -0 "$APP_PID" 2>/dev/null; then
        kill -TERM "$APP_PID" || true
        wait "$APP_PID" 2>/dev/null || true
    fi
    if [ -n "$ENCLAVE_ID" ]; then
        sudo nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID" 2>/dev/null || true
    fi
    jobs -p | xargs -r kill 2>/dev/null || true
}
trap cleanup EXIT

# Polls a command until it succeeds or the timeout (in seconds) is reached.
# Probe stderr is shown on timeout to aid diagnosis.
wait_for() {
    local desc="$1"
    local max="${2:-30}"
    shift 2
    local out
    for i in $(seq 1 "$max"); do
        if out="$("$@" 2>&1)"; then
            echo "$desc ready after ${i}s"
            return 0
        fi
        [ "$i" -eq "$max" ] && { echo "$desc not ready within ${max}s: $out" >&2; return 1; }
        sleep 1
    done
}

cd "$PROJECT_DIR" || exit 1

# Set up VSOCK bridges for enclave communication.
# Port 8000: env vars the enclave reads on startup; '|||'-delimited (APP_ENV only, rest empty).
socat VSOCK-LISTEN:8000,reuseaddr,fork SYSTEM:"printf '%s|||' '${APP_ENV}'" &
# Port 8001: enclave log output forwarded to host stdout
socat -u VSOCK-LISTEN:8001,reuseaddr,fork EXEC:"cat",stderr &

# Start the enclave in debug mode so PCR values are all zeros (predictable for CI testing)
sudo nitro-cli run-enclave \
    --cpu-count "$ENCLAVE_CPU" \
    --memory "$ENCLAVE_MEMORY" \
    --enclave-cid "$ENCLAVE_CID" \
    --eif-path "$EIF_PATH" \
    --debug-mode

ENCLAVE_ID="$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')"
if [ -z "$ENCLAVE_ID" ] || [ "$ENCLAVE_ID" = "null" ]; then
    echo "::error::Failed to start enclave — describe-enclaves returned no ID" >&2
    exit 1
fi
echo "Enclave started: $ENCLAVE_ID"

# Wait for the enclave gRPC server on vsock port 10350
wait_for "Enclave" 30 socat -u VSOCK-CONNECT:"$ENCLAVE_CID":10350,connect-timeout=1 /dev/null

# Start the host app with VSOCK transport enabled
AWS_REGION=us-east-1 \
    "${BIN_DIR}/amd64/app" --config "${PROJECT_DIR}/configs/app.yaml" run &
APP_PID=$!

# Wait for the host app gRPC health endpoint on port 10340
wait_for "Host app" 30 grpc_health_probe -addr=127.0.0.1:10340

go test -tags=smoke -count=1 "${PROJECT_DIR}/..."
