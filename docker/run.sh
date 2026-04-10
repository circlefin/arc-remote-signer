#!/bin/bash -e

readonly EIF_PATH="/usr/local/circle/enclave.eif"
readonly ENCLAVE_CPU_COUNT=${ENCLAVE_CPU_COUNT:-2}
readonly ENCLAVE_MEMORY_SIZE=${ENCLAVE_MEMORY_SIZE:-4096}
readonly ENCLAVE_CID=${ENCLAVE_CID:-16}

readonly PROXY_PORT=10340
readonly ENCLAVE_PORT=10350

# Global variable to store app PID
APP_PID=""
SHUTDOWN_IN_PROGRESS=false

log() {
  local message="${1}"
  local level="${2:-INFO}"
  jq -Mnc \
    --arg level "$level" \
    --arg message "$message" \
    'now as $t |
    {
        timestamp: ($t | todateiso8601),
        level:     $level,
        message:   $message
    }' >&2
}


# Shutdown the enclave and all background processes
shutdown() {
    # Prevent multiple invocations
    if [ "$SHUTDOWN_IN_PROGRESS" = true ]; then
        return 0
    fi
    SHUTDOWN_IN_PROGRESS=true

    log "Received signal, shutting down gracefully..."

    # Stop the app first
    if [ -n "$APP_PID" ]; then
        log "Stopping app (PID: $APP_PID)..."
        kill -TERM "$APP_PID" 2>/dev/null || true
        wait "$APP_PID" 2>/dev/null || true
    fi

    # Stop enclave if it's running
    if [ -n "${enclave_id:-}" ]; then
        log "Stopping Enclave with ID $enclave_id"
        nitro-cli terminate-enclave --enclave-id "$enclave_id" 2>/dev/null || true
    fi

    # Kill all remaining background processes
    jobs -p | xargs -r kill 2>/dev/null || true

    # Wait for cleanup to complete
    wait 2>/dev/null || true

    log "Stopped"
    exit 0
}

# Start the enclave
start_enclave() {
    log "Starting Enclave..."
    nitro-cli run-enclave ${EXTRA_NITRO_CLI_FLAGS:-} \
        --cpu-count "$ENCLAVE_CPU_COUNT" \
        --memory "$ENCLAVE_MEMORY_SIZE" \
        --enclave-cid "$ENCLAVE_CID" \
        --eif-path "$EIF_PATH"

    # Get enclave ID and store it globally
    enclave_id=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
    log "Started Enclave with ID $enclave_id"
}

# Start the app
start_app() {
    mkdir -p /usr/local/circle/logs
    touch /usr/local/circle/logs/app.log

    log "Starting app..."
    APP_PUBLIC_SERVER_PORT=${PROXY_PORT} /usr/local/circle/app --config /usr/local/circle/configs/app.yaml run &
    APP_PID=$!
    log "Started app with PID: $APP_PID"
}

setup_vsock_bridges() {
    log "Setting up VSOCK bridges..."

    # set nitro enclave environment variable
    socat VSOCK-LISTEN:8000,reuseaddr,fork SYSTEM:'echo \"$APP_ENV|$DD_SERVICE|$DD_ENV|$DD_ENTITY_ID\"' &


    # To mitigate the risk of sensitive information leakage, exporting tracing
    # data to Datadog is only enabled in non-production environments.
    if [ "$APP_ENV" != "prod" ]; then
        socat VSOCK-LISTEN:4317,reuseaddr,fork TCP:$OTEL_HOST:4317 & # OTLP traces
        socat VSOCK-LISTEN:8126,reuseaddr,fork TCP:$DD_AGENT_HOST:8126 & # Datadog APM traces
        socat VSOCK-LISTEN:8125,reuseaddr,fork TCP:$APP_CONFIG_OPTION_STATSD_HOST:$APP_CONFIG_OPTION_STATSD_PORT & # DogStatsD metrics
        socat -u VSOCK-LISTEN:8001,reuseaddr,fork EXEC:"cat",stderr &
    fi
}

# Setup signal handlers
trap shutdown SIGTERM SIGINT EXIT

if [ "${ENABLE_ENCLAVE:-false}" = "true" ]; then
    setup_vsock_bridges
    start_enclave
    sleep 3
fi


start_app

# Wait for the app process specifically
wait "$APP_PID"
