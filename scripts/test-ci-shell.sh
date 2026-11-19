#!/usr/bin/env bash

set -eu

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=SCRIPTDIR/test-harness.sh
source "$PROJECT_DIR/scripts/test-harness.sh"

extract_function() {
    local file="$1"
    local name="$2"

    awk -v start="${name}() {" '
        $0 == start { printing = 1 }
        printing { print }
        printing && /^}$/ { exit }
    ' "$file"
}

run_workflow_fixture() {
    local script_name="$1"
    local function_name="$2"
    local workflow_name="$3"
    local workflow_content="$4"
    local fixture_dir
    local function_source
    local status

    fixture_dir="$(mktemp -d)"
    mkdir -p "$fixture_dir/.github/workflows"
    printf 'target "signer-dev" {}\n' > "$fixture_dir/docker-bake.hcl"
    printf 'local-enclave-docker:\n\t@docker buildx bake signer-dev\ntest-all: test-it smoke\ntest-it: build up\nup: local-enclave-docker\n' \
        > "$fixture_dir/Makefile"
    printf '%s\n' "$workflow_content" > "$fixture_dir/.github/workflows/$workflow_name"
    function_source="$(extract_function "$PROJECT_DIR/scripts/$script_name" "$function_name")"

    if (
        PROJECT_DIR="$fixture_dir"
        eval "$function_source"
        "$function_name"
    ); then
        status=0
    else
        status=$?
    fi

    rm -rf "$fixture_dir"
    return "$status"
}

public_v2_smoke_uses_both_tag_sets() {
    local tests

    tests="$(cd "$PROJECT_DIR" && go test -tags=smoke -list '^TestPublicV2$' ./internal/smoke/public)" || return 1
    [ "$(grep -c '^TestPublicV2$' <<<"$tests")" -eq 1 ] || return 1
    tests="$(cd "$PROJECT_DIR" && go test -tags=smoke,nitro_smoke -list '^TestPublicV2$' ./internal/smoke/public)" || return 1
    [ "$(grep -c '^TestPublicV2$' <<<"$tests")" -eq 1 ]
}

public_ci_uses_the_test_target() {
    run_workflow_fixture test-dev-image.sh development_builds_select_signer_dev \
        pipeline-common-ci.yaml '        run: make test-all' || return 1
    ! run_workflow_fixture test-dev-image.sh development_builds_select_signer_dev \
        pipeline-common-ci.yaml '        run: time make test-all' || return 1
    ! run_workflow_fixture test-dev-image.sh development_builds_select_signer_dev \
        pipeline-common-ci.yaml '#        run: make test-all' || return 1
    ! run_workflow_fixture test-dev-image.sh development_builds_select_signer_dev \
        pipeline-common-ci.yaml '        run: make test-all-disabled'
}

bounded_runner_reaps_its_timer() {
    local function_source
    local started_at

    function_source="$(extract_function "$PROJECT_DIR/scripts/smoke-eif.sh" run_bounded)"
    started_at="$(date +%s)"
    (
        timeout() {
            shift 3
            "$@"
        }
        eval "$function_source"
        output="$(run_bounded 3 true)"
        : "$output"
    )

    [ $(( $(date +%s) - started_at )) -lt 2 ]
}

bounded_wait_reaps_its_timer() {
    local function_source
    local started_at

    function_source="$(extract_function "$PROJECT_DIR/docker/run.sh" wait_bounded)"
    started_at="$(date +%s)"
    (
        eval "$function_source"
        output="$({ sleep 0.1 & child_pid=$!; wait_bounded "$child_pid" 3; })"
        : "$output"
    )

    [ $(( $(date +%s) - started_at )) -lt 2 ]
}

run_cleanup_scenario() {
    local scenario="$1"
    local marker="${2:-}"
    local function_source

    function_source="$(extract_function "$PROJECT_DIR/scripts/smoke-eif.sh" stop_signer)
$(extract_function "$PROJECT_DIR/scripts/smoke-eif.sh" cleanup)"
    (
        eval "$function_source"
        # The dynamically loaded cleanup function uses this variable.
        # shellcheck disable=SC2034
        CONTAINER_NAME=smoke-test
        run_bounded() {
            shift
            if [ "$scenario" = inspect_unknown ] && [ "$1" = docker ] && [ "$2" = inspect ]; then
                return 2
            fi
            "$@"
        }
        docker() {
            if [ "$scenario" = stop_failure ] && [ "$1" = stop ]; then
                return 1
            fi
            if [ "$1" = inspect ] && [ "${2:-}" = --format ]; then
                printf '0\n'
            fi
            return 0
        }
        remove_container() {
            if [ -n "$marker" ]; then
                : > "$marker"
            fi
            [ "$scenario" != remove_failure ]
        }
        terminate_enclaves() {
            return 0
        }

        true
        cleanup
    ) 2>/dev/null
}

critical_cleanup_failure_changes_success() {
    run_cleanup_scenario remove_failure
    [ "$?" -eq 1 ]
}

non_graceful_shutdown_changes_success() {
    run_cleanup_scenario stop_failure
    [ "$?" -eq 1 ]
}

unknown_container_state_still_attempts_removal() {
    local marker
    local status

    marker="$(mktemp)"
    rm -f "$marker"
    run_cleanup_scenario inspect_unknown "$marker"
    status=$?
    [ "$status" -eq 1 ] && [ -e "$marker" ]
    status=$?
    rm -f "$marker"
    return "$status"
}

run_eif_restart_scenario() (
    local scenario="$1"
    local log_file="$2"
    local start_count=0
    local function_source
    function_source="$(extract_function "$PROJECT_DIR/scripts/smoke-eif.sh" run_smoke_phases)"
    eval "$function_source"
    start_signer() {
        start_count=$((start_count + 1))
        printf 'start %s\n' "$start_count" >> "$log_file"
        [ "$scenario" != second_start_failure ] || [ "$start_count" -ne 2 ]
    }
    stop_signer() {
        printf 'stop\n' >> "$log_file"
        [ "$scenario" != stop_failure ]
    }
    go() {
        if [ "${SMOKE_VERIFY_RESTART:-}" = true ]; then
            printf 'phase restart\n' >> "$log_file"
        else
            printf 'phase behavior\n' >> "$log_file"
        fi
    }
    run_smoke_phases
)

eif_restart_requires_a_successful_stop_and_second_start() (
    local fixture_dir
    fixture_dir="$(mktemp -d)"
    trap 'rm -rf "$fixture_dir"' EXIT
    run_eif_restart_scenario success "$fixture_dir/success" || return 1
    printf 'start 1\nphase behavior\nstop\nstart 2\nphase restart\n' > "$fixture_dir/expected"
    cmp -s "$fixture_dir/expected" "$fixture_dir/success" || return 1
    if run_eif_restart_scenario stop_failure "$fixture_dir/stop"; then return 1; fi
    printf 'start 1\nphase behavior\nstop\n' > "$fixture_dir/expected"
    cmp -s "$fixture_dir/expected" "$fixture_dir/stop" || return 1
    if run_eif_restart_scenario second_start_failure "$fixture_dir/start"; then return 1; fi
    printf 'start 1\nphase behavior\nstop\nstart 2\n' > "$fixture_dir/expected"
    cmp -s "$fixture_dir/expected" "$fixture_dir/start"
)

shared_harness_reports_all_results() {
    local output
    local stderr_file
    local result=0

    stderr_file="$(mktemp)"
    output="$(
        (
            failures=0
            success_status=0
            skip_status=0
            failure_status=0
            check 'The nested success case passes.' true || success_status=$?
            skip_check 'The nested skip case does not run.' 'The test requests this skip.' ||
                skip_status=$?
            check 'The nested failure case fails.' false || failure_status=$?
            printf 'failures=%s success_status=%s skip_status=%s failure_status=%s\n' \
                "$failures" "$success_status" "$skip_status" "$failure_status"
        ) 2>"$stderr_file"
    )"

    grep -Fxq 'ok - The nested success case passes.' <<<"$output" &&
        grep -Fxq 'skip - The nested skip case does not run. The test requests this skip.' <<<"$output" &&
        grep -Fxq 'not ok - The nested failure case fails.' "$stderr_file" &&
        ! grep -Fq 'not ok -' <<<"$output" &&
        grep -Fxq 'failures=1 success_status=0 skip_status=0 failure_status=0' \
            <<<"$output" || result=1

    rm -f "$stderr_file"
    return "$result"
}

errexit_harness_reports_all_results() {
    local output
    local status=0

    output="$(
        bash -eu -c '
            source "$1"
            check "The first child case fails." false
            skip_check "The child skip case does not run." "The test requests this skip."
            check "The second child case still runs." true
            printf "failures=%s\n" "$failures"
        ' _ "$PROJECT_DIR/scripts/test-harness.sh" 2>&1
    )" || status=$?

    [ "$status" -eq 0 ] &&
        grep -Fxq 'not ok - The first child case fails.' <<<"$output" &&
        grep -Fxq 'skip - The child skip case does not run. The test requests this skip.' \
            <<<"$output" &&
        grep -Fxq 'ok - The second child case still runs.' <<<"$output" &&
        grep -Fxq 'failures=1' <<<"$output"
}

check 'The run_bounded function returns without an orphan timer delay.' bounded_runner_reaps_its_timer
check 'The wait_bounded function returns without an orphan timer delay.' bounded_wait_reaps_its_timer
check 'A critical cleanup failure changes a successful result.' critical_cleanup_failure_changes_success
check 'A non-graceful signer shutdown changes a successful result.' non_graceful_shutdown_changes_success
check 'The cleanup starts container removal and gives a failure result for an unknown state.' unknown_container_state_still_attempts_removal
check 'The shared harness reports success, skip, and failure results.' shared_harness_reports_all_results
check 'The harness reports check and skip results when errexit is active.' errexit_harness_reports_all_results
check 'The public CI workflow uses the test target.' public_ci_uses_the_test_target
check 'Public v2 smoke is available under both smoke tag sets.' public_v2_smoke_uses_both_tag_sets
check 'The EIF restart requires a successful stop and second startup.' eif_restart_requires_a_successful_stop_and_second_start

exit "$failures"
