#!/usr/bin/env bash

set -eu

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=SCRIPTDIR/test-harness.sh
source "$PROJECT_DIR/scripts/test-harness.sh"

builder_builds_dedicated_enclave() {
    grep -Fq 'export CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH}' "$PROJECT_DIR/docker/Dockerfile" &&
        grep -Fq 'go build -o /out/enclave ./cmd/enclave' "$PROJECT_DIR/docker/Dockerfile"
}

production_signer_omits_enclave_runtime_assets() {
    local signer_stage

    signer_stage="$(sed -n '/^FROM runtime-base AS production-runtime$/,/^FROM runtime-base AS signer-dev$/p' "$PROJECT_DIR/docker/Dockerfile")"
    ! grep -Eq '/out/enclave|run_enclave(\.dev)?\.sh' <<<"$signer_stage" &&
        grep -Fq 'FROM production-runtime AS signer-with-enclave' "$PROJECT_DIR/docker/Dockerfile"
}

development_signer_contains_enclave_assets() {
    local signer_dev_stage

    signer_dev_stage="$(sed -n '/^FROM runtime-base AS signer-dev$/,/^FROM production-runtime AS signer-with-enclave$/p' "$PROJECT_DIR/docker/Dockerfile")"
    grep -Fq '/out/enclave ./enclave' <<<"$signer_dev_stage" &&
        grep -Fq 'docker/run_enclave.dev.sh ./run_enclave.dev.sh' <<<"$signer_dev_stage"
}

development_builds_select_signer_dev() {
    local internal_workflow="$PROJECT_DIR/.github/workflows/pipeline-common-golang.yaml"
    local public_workflow="$PROJECT_DIR/.github/workflows/pipeline-common-ci.yaml"

    grep -Fq 'target "signer-dev"' "$PROJECT_DIR/docker-bake.hcl" || return 1
    grep -Eq 'docker buildx bake .*signer-dev' "$PROJECT_DIR/Makefile" || return 1
    grep -Eq '^test-all:.*[[:space:]]test-it([[:space:]]|$)' "$PROJECT_DIR/Makefile" || return 1
    grep -Eq '^test-it:.*[[:space:]]up([[:space:]]|$)' "$PROJECT_DIR/Makefile" || return 1
    grep -Eq '^up:.*[[:space:]]local-enclave-docker([[:space:]]|$)' "$PROJECT_DIR/Makefile" || return 1

    if [ -f "$internal_workflow" ]; then
        grep -Fq 'bake_file_target: "signer-dev"' "$internal_workflow" || return 1
        return 0
    fi

    if [ ! -f "$public_workflow" ]; then
        printf 'The public CI workflow is not present: %s.\n' "$public_workflow" >&2
        return 1
    fi

    grep -Fqx '        run: make test-all' "$public_workflow"
}

development_entrypoint_uses_dedicated_enclave() {
    grep -Fq '/usr/local/circle/enclave' "$PROJECT_DIR/docker/run_enclave.dev.sh" &&
        ! grep -Fq '/usr/local/circle/app' "$PROJECT_DIR/docker/run_enclave.dev.sh" &&
        ! grep -Fq 'run-enclave' "$PROJECT_DIR/docker/run_enclave.dev.sh"
}

development_environment_allows_aws_kms() (
    export APP_PROVIDER_SECRETS_LOCALSTACK_ENABLED=false
    export APP_PROVIDER_AWSKMS_LOCALSTACK_ENABLED=false

    # shellcheck disable=SC1091
    source "$PROJECT_DIR/configs/.env.dev"

    [ "$APP_PROVIDER_SECRETS_LOCALSTACK_ENABLED" = false ] &&
        [ "$APP_PROVIDER_AWSKMS_LOCALSTACK_ENABLED" = false ]
)

check 'The app builder builds the dedicated enclave executable.' builder_builds_dedicated_enclave
check 'Production signer targets do not include enclave runtime assets.' production_signer_omits_enclave_runtime_assets
check 'The signer-dev target contains the dedicated enclave assets.' development_signer_contains_enclave_assets
check 'Local and CI development builds select signer-dev.' development_builds_select_signer_dev
check 'Development startup uses the dedicated enclave executable.' development_entrypoint_uses_dedicated_enclave
check 'The signer-dev target can use AWS KMS.' development_environment_allows_aws_kms

exit "$failures"
