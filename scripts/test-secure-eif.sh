#!/usr/bin/env bash

set -eu

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=SCRIPTDIR/test-harness.sh
source "$PROJECT_DIR/scripts/test-harness.sh"

enclave_launcher_is_silent() {
    grep -Fq 'exec >/dev/null 2>&1' "$PROJECT_DIR/docker/run_enclave.sh" &&
        grep -Fq 'exec env APP_PUBLIC_SERVER_PORT=10350' "$PROJECT_DIR/docker/run_enclave.sh"
}

enclave_has_no_host_observability_bridge() {
    ! grep -Eq 'APP_ENV|DD_(SERVICE|ENV|ENTITY_ID)|OTEL|socat|LOG_FIFO|8000|8001|4317|8125|8126' \
        "$PROJECT_DIR/docker/run_enclave.sh" "$PROJECT_DIR/docker/Dockerfile.enclave"
}

host_has_no_enclave_observability_bridge() {
    ! grep -Eq 'setup_vsock_bridges|VSOCK-LISTEN:(8000|8001|4317|8125|8126)' \
        "$PROJECT_DIR/docker/run.sh"
}

development_enclave_has_no_host_config() {
    awk '
        /^  enclave:$/ { in_enclave = 1; found_enclave = 1; next }
        in_enclave && /^  [[:alnum:]_-]+:$/ { in_enclave = 0 }
        in_enclave && /APP_ENV|AWS_PROFILE|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|APP_PROVIDER_AWSKMS_/ {
            found_host_config = 1
        }
        END { exit !found_enclave || found_host_config }
    ' "$PROJECT_DIR/deployments/docker-compose.yaml"
}

build_has_one_enclave_target() {
    [ "$(grep -Ec '^target "enclave"' "$PROJECT_DIR/docker-bake.hcl")" -eq 1 ] &&
        ! grep -Rqi 'enclave-debug' \
            "$PROJECT_DIR/docker-bake.hcl" \
            "$PROJECT_DIR/.github/workflows" \
            "$PROJECT_DIR/docker"
}

check 'The enclave launcher does not write to stdout or stderr.' enclave_launcher_is_silent
check 'The enclave image has no host observability bridge.' enclave_has_no_host_observability_bridge
check 'The host has no enclave observability bridge.' host_has_no_enclave_observability_bridge
check 'The host does not give configuration to the development enclave process.' development_enclave_has_no_host_config
check 'The build has one secure enclave target.' build_has_one_enclave_target

exit "$failures"
