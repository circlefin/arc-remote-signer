#!/bin/bash -e

readonly EIF_PATH="/usr/local/circle/enclave.eif"
readonly ENCLAVE_CPU_COUNT=${ENCLAVE_CPU_COUNT:-2}
readonly ENCLAVE_MEMORY_SIZE=${ENCLAVE_MEMORY_SIZE:-4096}
readonly ENCLAVE_CID=16

readonly VSOCKPROXY_READY_FILE=/tmp/vsockproxy.ready
readonly VSOCKPROXY_READY_TIMEOUT_DECISECONDS=30  # 30 * 0.1s = 3s

# Global variables to store process PIDs
APP_PID=""
VSOCKPROXY_PID=""
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

# Wait for a child to exit, then SIGKILL it if it remains alive past the
# ceiling. Polling avoids a watchdog process whose sleep child can outlive it.
wait_bounded() {
    local pid="$1"
    local timeout_s="${2:-35}"
    local deadline=$((SECONDS + timeout_s))

    while kill -0 "$pid" 2>/dev/null; do
        # On Linux, an exited child remains visible as a zombie until wait
        # reaps it; do not mistake that state for a running process.
        if [ -r "/proc/$pid/stat" ] && [ "$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null)" = "Z" ]; then
            break
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
            kill -KILL "$pid" 2>/dev/null || true
            break
        fi
        sleep 0.1
    done

    wait "$pid" 2>/dev/null || true
}


# Shutdown the enclave and all background processes.
# Order: app first (stop emitting RPCs) → vsockproxy (drain in-flight) →
# enclave terminate (acceptors close last).
shutdown() {
    local status="${1:-0}"

    trap - SIGTERM SIGINT EXIT
    # Prevent multiple invocations
    if [ "$SHUTDOWN_IN_PROGRESS" = true ]; then
        exit "$status"
    fi
    SHUTDOWN_IN_PROGRESS=true

    log "Received signal, shutting down gracefully..."

    # Stop the app first
    if [ -n "$APP_PID" ]; then
        log "Stopping app (PID: $APP_PID)..."
        kill -TERM "$APP_PID" 2>/dev/null || true
        wait_bounded "$APP_PID"
    fi

    # Stop vsockproxy after app so any in-flight KMS calls from inside
    # the enclave can drain through the proxy before its listeners
    # close.
    if [ -n "$VSOCKPROXY_PID" ]; then
        log "Stopping vsockproxy (PID: $VSOCKPROXY_PID)..."
        kill -TERM "$VSOCKPROXY_PID" 2>/dev/null || true
        wait_bounded "$VSOCKPROXY_PID"
    fi

    # Stop enclave if it's running
    if [ -n "${enclave_id:-}" ]; then
        log "Stopping Enclave with ID $enclave_id"
        nitro-cli terminate-enclave --enclave-id "$enclave_id" 2>/dev/null || true
    fi

    log "Stopped"
    exit "$status"
}

# Start the vsockproxy bridge as a separate process so its vsock listener
# is bound before nitro-cli starts the enclave (the first Initialize-time
# KMS call from inside the enclave races the listener bind otherwise).
start_vsockproxy() {
    log "Starting vsockproxy..."
    # Clear any stale sentinel from a previous run so the poll below cannot
    # observe a false-ready before the freshly started proxy binds.
    rm -f "$VSOCKPROXY_READY_FILE"
    # The proxy owns its listeners, so it is the only authoritative source of
    # "am I listening?": vsock listeners are not enumerable from the host via
    # /proc or the tools shipped in this image. run-vsockproxy creates
    # VSOCKPROXY_READY_FILE once byteproxy has bound every listener (in New,
    # before serving), so we gate on that file instead of probing the kernel.
    env VSOCKPROXY_READY_FILE="$VSOCKPROXY_READY_FILE" \
        /usr/local/circle/app \
        --config /usr/local/circle/config.yaml \
        run-vsockproxy &
    VSOCKPROXY_PID=$!
    log "Started vsockproxy with PID: $VSOCKPROXY_PID"

    # Wait until the proxy reports its listeners are bound. Track readiness
    # with an explicit flag so a success on the final iteration is not
    # misread as a timeout.
    local ready=false
    local attempts=0
    while [ "$attempts" -lt "$VSOCKPROXY_READY_TIMEOUT_DECISECONDS" ]; do
        if [ -e "$VSOCKPROXY_READY_FILE" ]; then
            # The sentinel only proves the proxy bound its listeners at some
            # point, not that it is still alive: it could have written the
            # file and then crashed (e.g. during serving). Re-check liveness
            # before trusting the sentinel so we never start the enclave
            # against a dead proxy.
            if ! kill -0 "$VSOCKPROXY_PID" 2>/dev/null; then
                log "vsockproxy exited after signaling ready (PID: $VSOCKPROXY_PID)" "ERROR"
                exit 1
            fi
            ready=true
            break
        fi
        # Surface a crash (config error, port conflict, ...) immediately
        # instead of waiting out the full readiness timeout.
        if ! kill -0 "$VSOCKPROXY_PID" 2>/dev/null; then
            log "vsockproxy exited unexpectedly (PID: $VSOCKPROXY_PID)" "ERROR"
            exit 1
        fi
        sleep 0.1
        attempts=$((attempts + 1))
    done
    if [ "$ready" != true ]; then
        log "vsockproxy did not report ready within 3s" "ERROR"
        exit 1
    fi
    log "vsockproxy is ready (listeners bound)"
}

# Start the enclave
start_enclave() {
    log "Starting Enclave..."
    nitro-cli run-enclave \
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
    /usr/local/circle/app --config /usr/local/circle/config.yaml run &
    APP_PID=$!
    log "Started app with PID: $APP_PID"
}

# Setup signal handlers. Preserve unexpected app failures through the EXIT trap.
trap 'shutdown 0' SIGTERM
trap 'shutdown 130' SIGINT
trap 'shutdown $?' EXIT

start_vsockproxy
start_enclave
sleep 3
start_app

# Wait for the app process specifically
wait "$APP_PID"
