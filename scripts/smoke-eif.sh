#!/usr/bin/env bash

# smoke-eif.sh runs smoke tests against the built signer-with-enclave image.
# Requires a 2xlarge-nitro-dind runner (Docker + Nitro Enclaves available).
#
# Usage:
#   IMAGE_REF=nitro-enclave-signer/signer-with-enclave:smoke scripts/smoke-eif.sh
#
# Environment variables:
#   IMAGE_REF                   Docker image reference to run (required)
#   AWS_ACCESS_KEY_ID           AWS access key from CI OIDC credentials (required)
#   AWS_SECRET_ACCESS_KEY       AWS secret key from CI OIDC credentials (required)
#   AWS_SESSION_TOKEN           AWS session token from CI OIDC credentials (required)
#   APP_SERVICE_SIGNER_KEYID    Signer key identifier (required)
#   APP_PROVIDER_AWSKMS_ARNS    Comma-separated AWS KMS key ARNs (required)
#   ENCLAVE_CPU                 CPU count for the enclave (default: 2)
#   ENCLAVE_MEMORY              Memory in MiB for the enclave (default: 4096)
set -eu

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export PROJECT_DIR

: "${IMAGE_REF:?IMAGE_REF must be set to the signer-with-enclave image to run}"
: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID must be set}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY must be set}"
: "${AWS_SESSION_TOKEN:?AWS_SESSION_TOKEN must be set}"
: "${APP_SERVICE_SIGNER_KEYID:?APP_SERVICE_SIGNER_KEYID must be set}"
: "${APP_PROVIDER_AWSKMS_ARNS:?APP_PROVIDER_AWSKMS_ARNS must be set}"
ENCLAVE_CPU="${ENCLAVE_CPU:-2}"
ENCLAVE_MEMORY="${ENCLAVE_MEMORY:-4096}"
CONTAINER_NAME="${CONTAINER_NAME:-smoke-signer-with-enclave}"
command -v timeout >/dev/null 2>&1 || {
    echo "timeout command is required on the Nitro runner" >&2
    exit 1
}
set -x

run_bounded() {
    local timeout_s="$1"
    shift

    timeout --signal=TERM --kill-after=5s "${timeout_s}s" "$@"
}

remove_container() {
    local timeout_s="$1"
    local container_name="$2"
    local output
    local status

    output="$(run_bounded "$timeout_s" docker rm -f "$container_name" 2>&1)" && return 0
    status=$?
    case "$output" in
        *"No such container"* | *"No such object"*) return 0 ;;
    esac

    echo "warning: failed to remove container $container_name: $output" >&2
    return "$status"
}

terminate_enclaves() {
    local cleanup_container="${CONTAINER_NAME}-nitro-cleanup"
    local cleanup_exit_code
    local cleanup_failed=0

    # The Nitro device belongs to the dind daemon, so use the tested image
    # rather than assuming nitro-cli and the device exist on the runner host.
    if ! remove_container 15 "$cleanup_container"; then
        return 1
    fi

    if ! run_bounded 15 docker run -d \
        --name "$cleanup_container" \
        --device=/dev/nitro_enclaves \
        --security-opt seccomp=unconfined \
        --entrypoint nitro-cli \
        "$IMAGE_REF" terminate-enclave --all >/dev/null; then
        echo "warning: failed to start bounded Nitro enclave cleanup" >&2
        cleanup_failed=1
    elif ! cleanup_exit_code="$(run_bounded 15 docker wait "$cleanup_container")"; then
        echo "warning: Nitro enclave cleanup failed or did not finish within 15s" >&2
        cleanup_failed=1
    elif [ "$cleanup_exit_code" != "0" ]; then
        echo "warning: Nitro enclave cleanup exited with code $cleanup_exit_code" >&2
        cleanup_failed=1
    fi

    if [ "$cleanup_failed" -ne 0 ]; then
        run_bounded 10 docker logs "$cleanup_container" >&2 || \
            echo "warning: failed to read Nitro enclave cleanup logs" >&2
    fi

    if ! remove_container 15 "$cleanup_container"; then
        cleanup_failed=1
    fi

    return "$cleanup_failed"
}

verify_image_contents() {
    local entrypoint

    entrypoint="$(run_bounded 15 docker inspect --format '{{json .Config.Entrypoint}}' "$IMAGE_REF")"
    test "$entrypoint" = '["/usr/local/circle/run.sh"]'

    run_bounded 30 docker run --rm \
        --entrypoint /bin/sh \
        "$IMAGE_REF" -eu -c '
            test -x /usr/local/circle/app
            test -f /usr/local/circle/config.yaml
            test -f /usr/local/circle/enclave.eif
            test -x /usr/local/circle/run.sh
            test ! -e /usr/local/circle/enclave
            test ! -e /usr/local/circle/configs
            test ! -e /usr/local/circle/deployments
            test ! -e /usr/local/circle/run_proxy.sh
            test ! -e /usr/local/circle/run_enclave.dev.sh
            if command -v socat >/dev/null 2>&1; then exit 1; fi
            nitro-cli --version >/dev/null
            if grep -aF "dev-session-token-placeholder" /usr/local/circle/app; then exit 1; fi
            if grep -aE "(localhost|localstack):4566" /usr/local/circle/app; then exit 1; fi
            if grep -Eqi "localstack|baseURL|nitroEnclave|ENABLE_ENCLAVE" /usr/local/circle/config.yaml; then exit 1; fi
            if grep -Eq "ENABLE_ENCLAVE|APP_PROVIDER_ENCLAVE_NITROENCLAVE_ENABLED|enclave_enabled|EXTRA_NITRO_CLI_FLAGS|--debug-mode" /usr/local/circle/run.sh; then exit 1; fi
        '
}

cleanup() {
    local status=$?
    local cleanup_failed=0
    local inspect_output
    local container_exists=false
    local container_absent=false
    local container_exit_code

    trap - EXIT INT TERM
    set +e

    if inspect_output="$(run_bounded 10 docker inspect "$CONTAINER_NAME" 2>&1)"; then
        container_exists=true
    else
        case "$inspect_output" in
            *"No such container"* | *"No such object"*) container_absent=true ;;
            *)
                echo "warning: failed to inspect container $CONTAINER_NAME: $inspect_output" >&2
                cleanup_failed=1
                ;;
        esac
    fi

    if [ "$container_exists" = true ]; then
        if ! run_bounded 85 docker stop --time 75 "$CONTAINER_NAME" >/dev/null; then
            echo "warning: signer container did not stop gracefully" >&2
            cleanup_failed=1
        elif ! container_exit_code="$(run_bounded 10 docker inspect --format '{{.State.ExitCode}}' "$CONTAINER_NAME")"; then
            echo "warning: failed to inspect signer container exit code" >&2
            cleanup_failed=1
        elif [ "$container_exit_code" != "0" ]; then
            echo "warning: signer container exited with code $container_exit_code" >&2
            cleanup_failed=1
        fi
        if ! run_bounded 10 docker logs "$CONTAINER_NAME"; then
            echo "warning: failed to read signer container logs" >&2
        fi
    fi

    # If inspect failed for an unknown reason, still attempt force-removal so a
    # transient daemon error cannot leave a credential-bearing container alive.
    if [ "$container_absent" = false ]; then
        if ! remove_container 15 "$CONTAINER_NAME"; then
            cleanup_failed=1
        fi
    fi

    if ! terminate_enclaves; then
        cleanup_failed=1
    fi

    if [ "$status" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT

handle_signal() {
    local status="$1"

    trap - INT TERM
    exit "$status"
}
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

# Polls a command while the signer container is running, until it succeeds or
# the timeout (in seconds) is reached. Probe stderr is shown on timeout.
wait_for() {
    local desc="$1"
    local max="${2:-30}"
    shift 2
    local out
    for i in $(seq 1 "$max"); do
        if [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null)" != "true" ]; then
            local state
            state="$(docker inspect --format 'status={{.State.Status}} exit_code={{.State.ExitCode}}' "$CONTAINER_NAME" 2>/dev/null || echo unavailable)"
            echo "$CONTAINER_NAME exited before $desc became ready ($state)" >&2
            return 1
        fi
        if out="$("$@" 2>&1)"; then
            echo "$desc ready after ${i}s"
            return 0
        fi
        [ "$i" -eq "$max" ] && { echo "$desc not ready within ${max}s: $out" >&2; return 1; }
        sleep 1
    done
}

cd "$PROJECT_DIR" || exit 1

verify_image_contents

if ! remove_container 15 "$CONTAINER_NAME"; then
    echo "failed to remove stale signer container" >&2
    exit 1
fi
if ! terminate_enclaves; then
    echo "failed to terminate stale Nitro enclaves" >&2
    exit 1
fi

# Debug mode permits per-PR EIFs but does not validate PCR-based identity policy.
docker run -d \
    --name "$CONTAINER_NAME" \
    --network host \
    --device=/dev/nitro_enclaves \
    --security-opt seccomp=unconfined \
    --entrypoint /bin/bash \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_REGION=us-east-1 \
    -e ENABLE_ENCLAVE=false \
    -e APP_ENV=dev \
    -e APP_PROVIDER_ENCLAVE_NITROENCLAVE_ENABLED=false \
    -e APP_PROVIDER_SECRETS_LOCALSTACK_ENABLED=true \
    -e APP_PROVIDER_AWSKMS_LOCALSTACK_ENABLED=true \
    -e APP_PROVIDER_ENCLAVE_CLIENT_BASEURL=127.0.0.1:1 \
    -e ENCLAVE_CID=1 \
    -e ENCLAVE_CPU_COUNT="$ENCLAVE_CPU" \
    -e ENCLAVE_MEMORY_SIZE="$ENCLAVE_MEMORY" \
    -e APP_SERVICE_SIGNER_KEYID="${APP_SERVICE_SIGNER_KEYID}" \
    -e APP_PROVIDER_AWSKMS_ARNS="${APP_PROVIDER_AWSKMS_ARNS}" \
    "$IMAGE_REF" -ec '
nitro-cli() {
    if [ "${1:-}" = "run-enclave" ]; then
        shift
        /usr/bin/nitro-cli run-enclave --debug-mode "$@"
        return
    fi
    /usr/bin/nitro-cli "$@"
}
source /usr/local/circle/run.sh
'

# Wait for the host app gRPC health endpoint exposed by the image on port 10340
wait_for "Host app" 60 grpc_health_probe -addr=127.0.0.1:10340

go test -tags=smoke,nitro_smoke -count=1 -timeout=5m "${PROJECT_DIR}/internal/smoke/..."
