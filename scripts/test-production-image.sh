#!/usr/bin/env bash

set -eu

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
failures=0

check() {
    local description="$1"
    shift

    if "$@"; then
        printf 'ok - %s\n' "$description"
    else
        printf 'not ok - %s\n' "$description" >&2
        failures=$((failures + 1))
    fi
}

production_builds_select_only_production_runtime_files() {
    local app_files
    local proxy_files
    local enclave_files
    local enclave_runtime_files

    app_files="$(GOOS=linux CGO_ENABLED=0 go list -tags=prod -f '{{join .GoFiles " "}}' "$PROJECT_DIR/internal/app")"
    proxy_files="$(GOOS=linux CGO_ENABLED=0 go list -tags=prod -f '{{join .GoFiles " "}}' "$PROJECT_DIR/internal/vsockproxy")"
    enclave_files="$(GOOS=linux CGO_ENABLED=1 go list -tags=prod -f '{{join .GoFiles " "}}' "$PROJECT_DIR/cmd/enclave")"
    enclave_runtime_files="$(GOOS=linux CGO_ENABLED=1 go list -tags=prod -f '{{join .GoFiles " "}}' "$PROJECT_DIR/internal/enclave")"

    grep -Fq 'runtime_prod.go' <<<"$app_files" &&
        ! grep -Fq 'runtime_dev.go' <<<"$app_files" &&
        grep -Fq 'runtime_prod_linux.go' <<<"$proxy_files" &&
        ! grep -Fq 'runtime_dev_linux.go' <<<"$proxy_files" &&
        grep -Fq 'run_enclave_prod.go' <<<"$enclave_files" &&
        ! grep -Fq 'run_enclave_dev.go' <<<"$enclave_files" &&
        grep -Fq 'runtime_prod_linux_cgo.go' <<<"$enclave_runtime_files" &&
        ! grep -Fq 'runtime_dev.go' <<<"$enclave_runtime_files"
}

docker_builds_production_executables() {
    grep -Fq 'go build -tags=prod -o /out/app-production .' "$PROJECT_DIR/docker/Dockerfile" &&
        grep -Fq 'go build -tags=prod' "$PROJECT_DIR/docker/Dockerfile.enclave"
}

docker_separates_production_and_development_stages() {
    grep -Fq 'FROM runtime-base AS production-runtime' "$PROJECT_DIR/docker/Dockerfile" &&
        grep -Fq 'FROM production-runtime AS signer' "$PROJECT_DIR/docker/Dockerfile" &&
        grep -Fq 'FROM runtime-base AS signer-dev' "$PROJECT_DIR/docker/Dockerfile" &&
        grep -Fq 'FROM production-runtime AS signer-with-enclave' "$PROJECT_DIR/docker/Dockerfile" &&
        ! grep -Fq 'FROM signer AS signer-with-enclave' "$PROJECT_DIR/docker/Dockerfile" &&
        ! grep -Fq 'FROM signer AS signer-dev' "$PROJECT_DIR/docker/Dockerfile"
}

production_stage_excludes_development_assets() {
    local production_stage

    production_stage="$(sed -n '/^FROM runtime-base AS production-runtime$/,/^FROM production-runtime AS signer$/p' "$PROJECT_DIR/docker/Dockerfile")"
    grep -Fq '/out/app-production ./app' <<<"$production_stage" &&
        grep -Fq 'configs/app.production.yaml ./config.yaml' <<<"$production_stage" &&
        ! grep -Eq 'deployments|/out/enclave|run_proxy|run_enclave\.dev|configs ./configs|\.env' <<<"$production_stage"
}

production_dockerfile_excludes_socat() {
    ! grep -Fqw 'socat' "$PROJECT_DIR/docker/Dockerfile"
}

development_stage_contains_development_assets() {
    local development_stage

    development_stage="$(sed -n '/^FROM runtime-base AS signer-dev$/,/^FROM production-runtime AS signer-with-enclave$/p' "$PROJECT_DIR/docker/Dockerfile")"
    grep -Fq '/out/app ./app' <<<"$development_stage" &&
        grep -Fq '/out/enclave ./enclave' <<<"$development_stage" &&
        grep -Fq 'configs ./configs' <<<"$development_stage" &&
        grep -Fq 'deployments ./deployments' <<<"$development_stage"
}

production_launcher_always_starts_nitro() {
    local launcher="$PROJECT_DIR/docker/run.sh"

    ! grep -Eq 'ENABLE_ENCLAVE|APP_PROVIDER_ENCLAVE_NITROENCLAVE_ENABLED|enclave_enabled' "$launcher" &&
        ! grep -Fq 'APP_PROVIDER_ENCLAVE_NITROENCLAVE_CID' "$launcher" &&
        ! grep -Eq 'EXTRA_NITRO_CLI_FLAGS|--debug-mode' "$launcher" &&
        grep -Fq 'readonly ENCLAVE_CID=16' "$launcher" &&
        grep -Fq 'start_vsockproxy' "$launcher" &&
        grep -Fq 'start_enclave' "$launcher" &&
        grep -Fq 'start_app' "$launcher"
}

production_config_excludes_development_modes() {
    local config="$PROJECT_DIR/configs/app.production.yaml"

    test -f "$config" &&
        ! grep -Eqi 'localstack|baseURL|nitroEnclave|ENABLE_ENCLAVE' "$config"
}

release_smoke_checks_image_contents() {
    local smoke="$PROJECT_DIR/scripts/smoke-eif.sh"

    grep -Fq 'verify_image_contents' "$smoke" &&
        grep -Fq "docker inspect --format '{{json .Config.Entrypoint}}'" "$smoke" &&
        grep -Fq "test \"\$entrypoint\" = '[\"/usr/local/circle/run.sh\"]'" "$smoke" &&
        grep -Fq 'test ! -e /usr/local/circle/enclave' "$smoke" &&
        grep -Fq 'test ! -e /usr/local/circle/configs' "$smoke" &&
        grep -Fq 'test ! -e /usr/local/circle/run_proxy.sh' "$smoke" &&
        grep -Fq 'if command -v socat >/dev/null 2>&1; then exit 1; fi' "$smoke" &&
        grep -Fq 'if grep -aF "dev-session-token-placeholder"' "$smoke" &&
        grep -Fq 'if grep -aE "(localhost|localstack):4566"' "$smoke" &&
        grep -Fq 'nitro-cli()' "$smoke" &&
        grep -Fq '/usr/bin/nitro-cli run-enclave --debug-mode "$@"' "$smoke" &&
        grep -Fq 'source /usr/local/circle/run.sh' "$smoke" &&
        grep -Fq -- '-e ENABLE_ENCLAVE=false' "$smoke" &&
        grep -Fq -- '-e APP_ENV=dev' "$smoke" &&
        grep -Fq -- '-e APP_PROVIDER_ENCLAVE_NITROENCLAVE_ENABLED=false' "$smoke" &&
        grep -Fq -- '-e APP_PROVIDER_SECRETS_LOCALSTACK_ENABLED=true' "$smoke" &&
        grep -Fq -- '-e APP_PROVIDER_AWSKMS_LOCALSTACK_ENABLED=true' "$smoke" &&
        grep -Fq -- '-e APP_PROVIDER_ENCLAVE_CLIENT_BASEURL=127.0.0.1:1' "$smoke" &&
        grep -Fq -- '-e ENCLAVE_CID=1' "$smoke"
}

check 'The production build selects only production runtime files.' production_builds_select_only_production_runtime_files
check 'Docker builds the production executables.' docker_builds_production_executables
check 'Docker separates the production and development stages.' docker_separates_production_and_development_stages
check 'The production stage excludes development assets.' production_stage_excludes_development_assets
check 'The production Dockerfile excludes socat.' production_dockerfile_excludes_socat
check 'The development stage contains development assets.' development_stage_contains_development_assets
check 'The production launcher always starts Nitro.' production_launcher_always_starts_nitro
check 'The production configuration excludes development modes.' production_config_excludes_development_modes
check 'The release smoke test checks the image contents.' release_smoke_checks_image_contents

exit "$failures"
