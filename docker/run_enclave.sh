#!/usr/bin/env bash

set -eux

PROJECT_DIR="$(dirname "$0")/.."
BIN_DIR="${PROJECT_DIR}/bin"
CMD_DIR="${PROJECT_DIR}/cmd"

export PROJECT_DIR
export BIN_DIR
export CMD_DIR

# Assign IP addresses to local loopback
ip addr add 127.0.0.1/32 dev lo
ip link set dev lo up

ENV_DATA=$(socat VSOCK-CONNECT:3:8000 -)
IFS='|' read -r APP_ENV DD_SERVICE DD_ENV DD_ENTITY_ID _ <<< "$ENV_DATA"

# Default APP_ENV to 'stg' if not provided by the host. This is a safe default
# as it enables non-production features like tracing.
export APP_ENV="${APP_ENV:-stg}"

# Export Datadog env vars if provided by host (non-empty check)
[ -n "$DD_ENV" ] && export DD_ENV
[ -n "$DD_ENTITY_ID" ] && export DD_ENTITY_ID
# Add "-enclave" suffix to distinguish enclave metrics from proxy
[ -n "$DD_SERVICE" ] && export DD_SERVICE="${DD_SERVICE}-enclave"

# Create a FIFO for logging
LOG_FIFO=/tmp/log.fifo
mkfifo "$LOG_FIFO"

# outbound
if [ "$APP_ENV" != "prod" ]; then
    export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317
    socat TCP-LISTEN:4317,fork,reuseaddr VSOCK-CONNECT:3:4317 & # OTLP traces
    socat TCP-LISTEN:8126,fork,reuseaddr VSOCK-CONNECT:3:8126 & # Datadog APM traces
    socat TCP-LISTEN:8125,fork,reuseaddr VSOCK-CONNECT:3:8125 & # DogStatsD metrics
    # Redirect FIFO to vsock and stdout
    ( cat <"$LOG_FIFO" | tee >(socat - VSOCK-CONNECT:3:8001) ) &
    LOG_PID=$!
else
    # Make sure we drain the fifo if not sending to vsock
    cat >/dev/null < "$LOG_FIFO" &
    LOG_PID=$!
fi

# redirect stdout and stderr of enclave to FIFO
APP_PUBLIC_SERVER_PORT=10350 /usr/local/circle/app \
    --enclave-config /usr/local/circle/configs/enclave.yaml run-enclave \
    2>&1 > "$LOG_FIFO" &
APP_PID=$!

cleanup() {
    kill "$APP_PID" || true
    kill "$LOG_PID" || true
    rm -f "$LOG_FIFO"
}

trap cleanup TERM INT

wait "$APP_PID"
