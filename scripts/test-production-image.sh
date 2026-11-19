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

prepare_apt_retry_test() {
    local test_bin_dir="$1"

    mkdir -p "$test_bin_dir"
    cat >"$test_bin_dir/apt-get" <<'EOF'
#!/usr/bin/env bash
set -eu

printf 'apt-get %s\n' "$*" >>"$RETRY_TEST_LOG"
if [[ "${RETRY_TEST_REQUIRE_TIMEOUTS:-false}" == true ]]; then
    if [[ " $* " == *" --no-download "* ]]; then
        if [[ "${RETRY_TEST_UNDER_DEADLINE:-false}" == true || ! -f "$RETRY_TEST_DOWNLOAD_READY" ||
            " $* " != *" install -y --no-install-recommends iproute2 ca-certificates "* ]]; then
            exit 64
        fi
        read -r offline_count <"$RETRY_TEST_OFFLINE_COUNT"
        offline_count=$((offline_count + 1))
        printf '%s\n' "$offline_count" >"$RETRY_TEST_OFFLINE_COUNT"
        if ((offline_count <= RETRY_TEST_FAIL_OFFLINE)); then
            exit 1
        fi
        exit 0
    fi
    if [[ "${RETRY_TEST_UNDER_DEADLINE:-false}" != true ]]; then
        printf 'Network acquisition has no attempt deadline.\n' >&2
        exit 64
    fi
    for option in Acquire::Retries=10 Acquire::http::Timeout=30 Acquire::https::Timeout=30; do
        if [[ " $* " != *" $option "* ]]; then
            exit 64
        fi
    done
fi
for argument in "$@"; do
    if [[ "$argument" == update && -n "${RETRY_TEST_UPDATE_COUNT:-}" ]]; then
        read -r update_count <"$RETRY_TEST_UPDATE_COUNT"
        update_count=$((update_count + 1))
        printf '%s\n' "$update_count" >"$RETRY_TEST_UPDATE_COUNT"
        if ((update_count <= RETRY_TEST_FAIL_UPDATES)); then
            printf 'W: Some index files failed to download.\n' >&2
            if [[ " $* " == *" --error-on=any "* ]]; then
                exit 100
            fi
        fi
    fi
    if [[ "$argument" == install ]]; then
        if [[ "${RETRY_TEST_REQUIRE_TIMEOUTS:-false}" == true &&
            ( " $* " != *" --download-only "* ||
            " $* " != *" install -y --no-install-recommends iproute2 ca-certificates "* ) ]]; then
            exit 64
        fi
        read -r install_count <"$RETRY_TEST_COUNT"
        install_count=$((install_count + 1))
        printf '%s\n' "$install_count" >"$RETRY_TEST_COUNT"
        if ((install_count <= RETRY_TEST_FAIL_INSTALLS)); then
            exit 1
        fi
        if [[ "${RETRY_TEST_REQUIRE_TIMEOUTS:-false}" == true ]]; then
            printf 'ready\n' >"$RETRY_TEST_DOWNLOAD_READY"
        fi
    fi
done
EOF
    cat >"$test_bin_dir/rm" <<'EOF'
#!/usr/bin/env bash
set -eu

if [[ "$#" -lt 2 || "$1" != -rf ]]; then
    exit 1
fi
shift
for path in "$@"; do
    if [[ "$path" != /var/lib/apt/lists/* ]]; then
        exit 1
    fi
done
printf 'rm -rf /var/lib/apt/lists/*\n' >>"$RETRY_TEST_LOG"
EOF
    cat >"$test_bin_dir/sleep" <<'EOF'
#!/usr/bin/env bash
set -eu
printf 'sleep %s\n' "$*" >>"$RETRY_TEST_LOG"
EOF
    cat >"$test_bin_dir/timeout" <<'EOF'
#!/usr/bin/env bash
set -eu

printf 'timeout\n' >>"$RETRY_TEST_LOG"
if [[ "$1" != --verbose || "$2" != --kill-after=5s || "$3" != 240s || "$4" != sh || "$5" != -c ]]; then
    exit 64
fi
read -r timeout_count <"$RETRY_TEST_TIMEOUT_COUNT"
timeout_count=$((timeout_count + 1))
printf '%s\n' "$timeout_count" >"$RETRY_TEST_TIMEOUT_COUNT"
if ((timeout_count <= RETRY_TEST_FAIL_TIMEOUTS)); then
    exit "$RETRY_TEST_TIMEOUT_STATUS"
fi
shift 3
export RETRY_TEST_UNDER_DEADLINE=true
exec "$@"
EOF
    chmod +x "$test_bin_dir/apt-get" "$test_bin_dir/rm" "$test_bin_dir/sleep" "$test_bin_dir/timeout"
}

nitro_cli_package_install_retries_then_succeeds() (
    local retry_script="$PROJECT_DIR/docker/install-nitro-cli-build-dependencies.sh"
    local test_dir
    test_dir="$(mktemp -d)"
    trap '/bin/rm -rf "$test_dir"' EXIT

    prepare_apt_retry_test "$test_dir/bin"
    printf '0\n' >"$test_dir/install-count"
    cat >"$test_dir/expected.log" <<'EOF'
rm -rf /var/lib/apt/lists/*
apt-get -o Acquire::Retries=3 update --error-on=any
apt-get -o Acquire::Retries=3 install -y --no-install-recommends musl-tools
sleep 10
rm -rf /var/lib/apt/lists/*
apt-get -o Acquire::Retries=3 update --error-on=any
apt-get -o Acquire::Retries=3 install -y --no-install-recommends musl-tools
sleep 20
rm -rf /var/lib/apt/lists/*
apt-get -o Acquire::Retries=3 update --error-on=any
apt-get -o Acquire::Retries=3 install -y --no-install-recommends musl-tools
rm -rf /var/lib/apt/lists/*
EOF

    env PATH="$test_dir/bin:$PATH" \
        RETRY_TEST_LOG="$test_dir/actual.log" \
        RETRY_TEST_COUNT="$test_dir/install-count" \
        RETRY_TEST_FAIL_INSTALLS=2 \
        sh "$retry_script" &&
        cmp -s "$test_dir/expected.log" "$test_dir/actual.log"
)

nitro_cli_package_install_stops_after_three_failures() (
    local retry_script="$PROJECT_DIR/docker/install-nitro-cli-build-dependencies.sh"
    local test_dir
    test_dir="$(mktemp -d)"
    trap '/bin/rm -rf "$test_dir"' EXIT

    prepare_apt_retry_test "$test_dir/bin"
    printf '0\n' >"$test_dir/install-count"
    cat >"$test_dir/expected.log" <<'EOF'
rm -rf /var/lib/apt/lists/*
apt-get -o Acquire::Retries=3 update --error-on=any
apt-get -o Acquire::Retries=3 install -y --no-install-recommends musl-tools
sleep 10
rm -rf /var/lib/apt/lists/*
apt-get -o Acquire::Retries=3 update --error-on=any
apt-get -o Acquire::Retries=3 install -y --no-install-recommends musl-tools
sleep 20
rm -rf /var/lib/apt/lists/*
apt-get -o Acquire::Retries=3 update --error-on=any
apt-get -o Acquire::Retries=3 install -y --no-install-recommends musl-tools
EOF

    if env PATH="$test_dir/bin:$PATH" \
        RETRY_TEST_LOG="$test_dir/actual.log" \
        RETRY_TEST_COUNT="$test_dir/install-count" \
        RETRY_TEST_FAIL_INSTALLS=3 \
        sh "$retry_script"; then
        return 1
    fi
    cmp -s "$test_dir/expected.log" "$test_dir/actual.log"
)

docker_uses_nitro_cli_package_install_script() {
    grep -Fq 'COPY --chmod=0755 docker/install-nitro-cli-build-dependencies.sh /usr/local/bin/' "$PROJECT_DIR/docker/Dockerfile" &&
        grep -Fq '/usr/local/bin/install-nitro-cli-build-dependencies.sh' "$PROJECT_DIR/docker/Dockerfile"
}

enclave_runtime_package_install_handles_failures() (
    local retry_script="$PROJECT_DIR/docker/install-enclave-runtime-dependencies.sh"
    local test_dir
    local scenario failure_phase failures want_success want_updates want_downloads want_installs want_attempts
    local fail_updates fail_installs fail_offline fail_timeouts timeout_status
    local scenario_dir got_status got_updates got_downloads got_installs got_attempts got_waits

    test -f "$retry_script" || return 1
    test_dir="$(mktemp -d)"
    trap '/bin/rm -rf "$test_dir"' EXIT
    prepare_apt_retry_test "$test_dir/bin"

    while read -r scenario failure_phase failures want_success want_updates want_downloads want_installs want_attempts; do
        scenario_dir="$test_dir/$scenario"
        mkdir -p "$scenario_dir"
        printf '0\n' >"$scenario_dir/update-count"
        printf '0\n' >"$scenario_dir/install-count"
        printf '0\n' >"$scenario_dir/offline-count"
        printf '0\n' >"$scenario_dir/timeout-count"
        fail_updates=0
        fail_installs=0
        fail_offline=0
        fail_timeouts=0
        timeout_status=124
        case "$failure_phase" in
            update) fail_updates="$failures" ;;
            install) fail_installs="$failures" ;;
            offline) fail_offline="$failures" ;;
            timeout124|timeout137)
                fail_timeouts="$failures"
                timeout_status="${failure_phase#timeout}"
                ;;
            none) ;;
            *) return 1 ;;
        esac
        if env PATH="$test_dir/bin:$PATH" \
            RETRY_TEST_LOG="$scenario_dir/actual.log" \
            RETRY_TEST_COUNT="$scenario_dir/install-count" \
            RETRY_TEST_UPDATE_COUNT="$scenario_dir/update-count" \
            RETRY_TEST_FAIL_UPDATES="$fail_updates" \
            RETRY_TEST_FAIL_INSTALLS="$fail_installs" \
            RETRY_TEST_OFFLINE_COUNT="$scenario_dir/offline-count" \
            RETRY_TEST_FAIL_OFFLINE="$fail_offline" \
            RETRY_TEST_DOWNLOAD_READY="$scenario_dir/download-ready" \
            RETRY_TEST_TIMEOUT_COUNT="$scenario_dir/timeout-count" \
            RETRY_TEST_FAIL_TIMEOUTS="$fail_timeouts" \
            RETRY_TEST_TIMEOUT_STATUS="$timeout_status" \
            RETRY_TEST_REQUIRE_TIMEOUTS=true \
            sh "$retry_script" >"$scenario_dir/output.log" 2>&1; then
            got_status=0
        else
            got_status=$?
        fi
        if [[ "$want_success" == true && "$got_status" -ne 0 ]] ||
            [[ "$want_success" == false && "$got_status" -eq 0 ]]; then
            printf '%s: unexpected exit status %s\n' "$scenario" "$got_status" >&2
            cat "$scenario_dir/output.log" >&2
            return 1
        fi
        read -r got_updates <"$scenario_dir/update-count"
        read -r got_downloads <"$scenario_dir/install-count"
        read -r got_installs <"$scenario_dir/offline-count"
        read -r got_attempts <"$scenario_dir/timeout-count"
        got_waits="$(grep -c '^sleep ' "$scenario_dir/actual.log" || true)"
        if [[ "$got_updates" != "$want_updates" || "$got_downloads" != "$want_downloads" ||
            "$got_installs" != "$want_installs" || "$got_attempts" != "$want_attempts" ||
            "$got_waits" -ne "$((want_attempts - 1))" ]]; then
            printf '%s: unexpected update/download/install/attempt/wait counts: %s/%s/%s/%s/%s\n' \
                "$scenario" "$got_updates" "$got_downloads" "$got_installs" "$got_attempts" "$got_waits" >&2
            return 1
        fi
        if ! awk '
            $1 == "rm" { cleared = 1 }
            $1 == "apt-get" && / update( |$)/ {
                if (!cleared) exit 1
                cleared = 0
            }
        ' "$scenario_dir/actual.log"; then
            printf '%s: package indexes were not cleared before each update\n' "$scenario" >&2
            return 1
        fi
        if [[ "$want_attempts" -eq 3 ]]; then
            grep -Fxq 'sleep 10' "$scenario_dir/actual.log" &&
                grep -Fxq 'sleep 20' "$scenario_dir/actual.log" || return 1
        fi
    done <<'EOF'
immediate_success none 0 true 1 1 1 1
install_recovers install 2 true 3 3 1 3
install_exhausts install 3 false 3 3 0 3
index_recovers update 2 true 3 1 1 3
index_exhausts update 3 false 3 0 0 3
offline_recovers offline 2 true 3 3 3 3
offline_exhausts offline 3 false 3 3 3 3
timeout_recovers timeout124 2 true 1 1 1 3
timeout_exhausts timeout124 3 false 0 0 0 3
kill_recovers timeout137 2 true 1 1 1 3
kill_exhausts timeout137 3 false 0 0 0 3
EOF
)

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
check 'The Nitro CLI package install retries temporary failures.' nitro_cli_package_install_retries_then_succeeds
check 'The Nitro CLI package install stops after three failures.' nitro_cli_package_install_stops_after_three_failures
check 'Docker uses the Nitro CLI package install script.' docker_uses_nitro_cli_package_install_script
check 'The enclave runtime package install retries temporary failures and stops on persistent failures.' enclave_runtime_package_install_handles_failures
check 'Docker separates the production and development stages.' docker_separates_production_and_development_stages
check 'The production stage excludes development assets.' production_stage_excludes_development_assets
check 'The production Dockerfile excludes socat.' production_dockerfile_excludes_socat
check 'The development stage contains development assets.' development_stage_contains_development_assets
check 'The production launcher always starts Nitro.' production_launcher_always_starts_nitro
check 'The production configuration excludes development modes.' production_config_excludes_development_modes
check 'The release smoke test checks the image contents.' release_smoke_checks_image_contents

exit "$failures"
