#!/usr/bin/env bash

set -eu

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=SCRIPTDIR/test-harness.sh
source "$PROJECT_DIR/scripts/test-harness.sh"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

merge() {
    bash "$PROJECT_DIR/scripts/merge-production-coverage.sh" "$@"
}

fails_with() {
    local expected="$1"
    shift
    local output

    if output="$("$@" 2>&1)"; then
        return 1
    fi
    grep -Fq "$expected" <<<"$output"
}

missing_or_empty_arguments_are_rejected() {
    local coverage="$work_dir/arguments-coverage.out"
    local production="$work_dir/arguments-production.out"

    printf 'mode: set\nexample.com/signer/internal/app/app.go:1.1,2.2 1 1\n' >"$coverage"
    printf 'mode: set\nexample.com/signer/internal/app/runtime_prod.go:1.1,2.2 1 1\n' >"$production"

    fails_with 'MISSING_ARGUMENT [BASE_PROFILE]' merge || return 1
    fails_with 'MISSING_ARGUMENT [PRODUCTION_PROFILE]' merge "$coverage" || return 1
    fails_with 'MISSING_ARGUMENT [PACKAGE_PREFIX]' \
        merge "$coverage" "$production" || return 1
    fails_with 'MISSING_ARGUMENT [BASE_PROFILE]' \
        merge '' "$production" 'internal/app/' || return 1
    fails_with 'MISSING_ARGUMENT [PRODUCTION_PROFILE]' \
        merge "$coverage" '' 'internal/app/' || return 1
    fails_with 'MISSING_ARGUMENT [PACKAGE_PREFIX]' merge "$coverage" "$production" ''
}

new_production_files_are_merged() {
    local coverage="$work_dir/merge-coverage.out"
    local production="$work_dir/merge-production.out"
    local expected="$work_dir/merge-expected.out"

    cat >"$coverage" <<'EOF'
mode: set
example.com/signer/internal/app/app.go:10.1,12.2 1 1
example.com/signer/internal/common/config.go:5.1,7.2 1 1
EOF
    cat >"$production" <<'EOF'
mode: set
example.com/signer/internal/app/app.go:10.1,12.2 1 0
example.com/signer/internal/app/runtime_prod.go:20.1,22.2 1 1
example.com/signer/internal/app/runtime_prod_policy.go:30.1,32.2 1 0
example.com/signer/internal/common/config.go:5.1,7.2 1 1
EOF
    cat >"$expected" <<'EOF'
mode: set
example.com/signer/internal/app/app.go:10.1,12.2 1 1
example.com/signer/internal/common/config.go:5.1,7.2 1 1
example.com/signer/internal/app/runtime_prod.go:20.1,22.2 1 1
example.com/signer/internal/app/runtime_prod_policy.go:30.1,32.2 1 0
EOF

    merge "$coverage" "$production" 'internal/app/' &&
        diff -u "$expected" "$coverage"
}

coverage_mode_mismatch_is_rejected() {
    local coverage="$work_dir/mismatch-coverage.out"
    local production="$work_dir/mismatch-production.out"
    local output

    printf 'mode: set\nexample.com/signer/internal/app/app.go:1.1,2.2 1 1\n' >"$coverage"
    printf 'mode: atomic\nexample.com/signer/internal/app/runtime_prod.go:1.1,2.2 1 1\n' >"$production"

    if output="$(merge "$coverage" "$production" 'internal/app/' 2>&1)"; then
        return 1
    fi

    grep -Fq 'COVERAGE_MODE_MISMATCH' <<<"$output" &&
        grep -Fq 'mode: set and mode: atomic' <<<"$output"
}

missing_mode_header_is_rejected() {
    local coverage="$work_dir/header-coverage.out"
    local production="$work_dir/header-production.out"

    cat >"$coverage" <<'EOF'
example.com/signer/internal/app/a.go:1.1,2.2 1 1
example.com/signer/internal/app/b.go:1.1,2.2 1 1
EOF
    cat >"$production" <<'EOF'
example.com/signer/internal/app/a.go:1.1,2.2 1 1
example.com/signer/internal/app/a.go:3.1,4.2 1 0
EOF

    fails_with "INVALID_MODE_HEADER [$coverage]" \
        merge "$coverage" "$production" 'internal/app/'
}

production_missing_mode_header_is_rejected() {
    local coverage="$work_dir/production-header-coverage.out"
    local production="$work_dir/production-header-production.out"

    printf 'mode: set\nexample.com/signer/internal/app/app.go:1.1,2.2 1 1\n' >"$coverage"
    printf 'example.com/signer/internal/app/runtime_prod.go:1.1,2.2 1 1\n' >"$production"

    fails_with "INVALID_MODE_HEADER [$production]" \
        merge "$coverage" "$production" 'internal/app/'
}

missing_production_profile_is_rejected() {
    local coverage="$work_dir/missing-coverage.out"

    printf 'mode: set\nexample.com/signer/internal/app/app.go:1.1,2.2 1 1\n' >"$coverage"

    fails_with 'PRODUCTION_PROFILE_MISSING_OR_EMPTY' \
        merge "$coverage" "$work_dir/does-not-exist.out" 'internal/app/'
}

empty_base_profile_is_rejected() {
    local coverage="$work_dir/empty-coverage.out"
    local production="$work_dir/empty-production.out"

    : >"$coverage"
    printf 'mode: set\nexample.com/signer/internal/app/runtime_prod.go:1.1,2.2 1 1\n' >"$production"

    fails_with 'BASE_PROFILE_MISSING_OR_EMPTY' \
        merge "$coverage" "$production" 'internal/app/'
}

unreadable_profiles_are_rejected() {
    local coverage="$work_dir/unreadable-coverage.out"
    local production="$work_dir/unreadable-production.out"

    printf 'mode: set\nexample.com/signer/internal/app/app.go:1.1,2.2 1 1\n' >"$coverage"
    printf 'mode: set\nexample.com/signer/internal/app/runtime_prod.go:1.1,2.2 1 1\n' >"$production"

    chmod 000 "$coverage"
    fails_with "BASE_PROFILE_UNREADABLE [$coverage]" \
        merge "$coverage" "$production" 'internal/app/' || return 1

    chmod 600 "$coverage"
    chmod 000 "$production"

    fails_with "PRODUCTION_PROFILE_UNREADABLE [$production]" \
        merge "$coverage" "$production" 'internal/app/'
}

prepare_awk_failure() {
    local coverage="$1"
    local production="$2"
    local fake_bin="$3"

    printf 'mode: set\nexample.com/signer/internal/app/app.go:1.1,2.2 1 1\n' >"$coverage"
    printf 'mode: set\nexample.com/signer/internal/app/runtime_prod.go:1.1,2.2 1 1\n' >"$production"
    mkdir -p "$fake_bin"
    printf '#!/usr/bin/env bash\nprintf "example.com/signer/internal/app/partial.go:1.1,2.2 1 1\\n"\nexit 2\n' >"$fake_bin/awk"
    chmod 700 "$fake_bin/awk"
}

merge_fails_after_awk() {
    local coverage="$1"
    local production="$2"
    local fake_bin="$3"

    PATH="$fake_bin:$PATH" fails_with "COVERAGE_MERGE_FAILED [$production -> $coverage]" \
        merge "$coverage" "$production" 'internal/app/'
}

awk_fatal_error_preserves_base_profile() {
    local coverage="$work_dir/preserve-coverage.out"
    local production="$work_dir/preserve-production.out"
    local before="$work_dir/preserve-before.out"
    local fake_bin="$work_dir/preserve-fake-bin"

    prepare_awk_failure "$coverage" "$production" "$fake_bin"
    cp "$coverage" "$before"

    merge_fails_after_awk "$coverage" "$production" "$fake_bin" || return 1
    diff -u "$before" "$coverage"
}

awk_fatal_error_removes_temp_profiles() {
    local profile_dir="$work_dir/cleanup"
    local coverage="$profile_dir/coverage.out"
    local production="$profile_dir/production.out"
    local expected="$work_dir/cleanup-expected.out"
    local fake_bin="$work_dir/cleanup-fake-bin"

    mkdir -p "$profile_dir"
    prepare_awk_failure "$coverage" "$production" "$fake_bin"
    printf 'coverage.out\nproduction.out\n' >"$expected"

    merge_fails_after_awk "$coverage" "$production" "$fake_bin" || return 1
    LC_ALL=C ls -A1 "$profile_dir" | diff -u "$expected" -
}

first_temp_profile_failure_uses_stable_diagnostic() {
    local coverage="$work_dir/first-temp-coverage.out"
    local production="$work_dir/first-temp-production.out"
    local fake_bin="$work_dir/first-temp-fake-bin"

    printf 'mode: set\nexample.com/signer/internal/app/app.go:1.1,2.2 1 1\n' >"$coverage"
    printf 'mode: set\nexample.com/signer/internal/app/runtime_prod.go:1.1,2.2 1 1\n' >"$production"
    mkdir -p "$fake_bin"
    printf '#!/usr/bin/env bash\nexit 1\n' >"$fake_bin/mktemp"
    chmod 700 "$fake_bin/mktemp"

    PATH="$fake_bin:$PATH" fails_with \
        "TEMP_PROFILE_CREATE_FAILED [${coverage}.additions.XXXXXX]" \
        merge "$coverage" "$production" 'internal/app/'
}

second_temp_profile_failure_removes_first_temp_profile() {
    local profile_dir="$work_dir/second-temp"
    local coverage="$profile_dir/coverage.out"
    local production="$profile_dir/production.out"
    local expected="$work_dir/second-temp-expected.out"
    local before="$work_dir/second-temp-before.out"
    local fake_bin="$work_dir/second-temp-fake-bin"

    mkdir -p "$profile_dir" "$fake_bin"
    printf 'mode: set\nexample.com/signer/internal/app/app.go:1.1,2.2 1 1\n' >"$coverage"
    printf 'mode: set\nexample.com/signer/internal/app/runtime_prod.go:1.1,2.2 1 1\n' >"$production"
    cp "$coverage" "$before"
    printf 'coverage.out\nproduction.out\n' >"$expected"
    cat >"$fake_bin/mktemp" <<'EOF'
#!/usr/bin/env bash

case "$1" in
    *.additions.XXXXXX)
        temp_profile="${1%XXXXXX}TEST"
        : >"$temp_profile"
        printf '%s\n' "$temp_profile"
        ;;
    *) exit 1 ;;
esac
EOF
    chmod 700 "$fake_bin/mktemp"

    PATH="$fake_bin:$PATH" fails_with \
        "TEMP_PROFILE_CREATE_FAILED [${coverage}.merged.XXXXXX]" \
        merge "$coverage" "$production" 'internal/app/' || return 1
    diff -u "$before" "$coverage" || return 1
    LC_ALL=C ls -A1 "$profile_dir" | diff -u "$expected" -
}

final_profile_command_failure_uses_stable_diagnostic() {
    local command_name="$1"
    local expected_identifier="$2"
    local profile_dir="$work_dir/${command_name}-failure"
    local coverage="$profile_dir/coverage.out"
    local production="$profile_dir/production.out"
    local expected="$work_dir/${command_name}-failure-expected.out"
    local before="$work_dir/${command_name}-failure-before.out"
    local fake_bin="$work_dir/${command_name}-failure-fake-bin"

    mkdir -p "$profile_dir" "$fake_bin"
    printf 'mode: set\nexample.com/signer/internal/app/app.go:1.1,2.2 1 1\n' >"$coverage"
    printf 'mode: set\nexample.com/signer/internal/app/runtime_prod.go:1.1,2.2 1 1\n' >"$production"
    cp "$coverage" "$before"
    printf 'coverage.out\nproduction.out\n' >"$expected"
    printf '#!/usr/bin/env bash\nexit 1\n' >"$fake_bin/$command_name"
    chmod 700 "$fake_bin/$command_name"

    PATH="$fake_bin:$PATH" fails_with "$expected_identifier" \
        merge "$coverage" "$production" 'internal/app/' || return 1
    diff -u "$before" "$coverage" || return 1
    LC_ALL=C ls -A1 "$profile_dir" | diff -u "$expected" -
}

zero_additions_is_allowed() {
    local coverage="$work_dir/noop-coverage.out"
    local production="$work_dir/noop-production.out"
    local expected="$work_dir/noop-expected.out"

    printf 'mode: set\nexample.com/signer/internal/app/app.go:1.1,2.2 1 1\n' >"$coverage"
    printf 'mode: set\nexample.com/signer/internal/app/app.go:1.1,2.2 1 0\n' >"$production"
    cp "$coverage" "$expected"

    merge "$coverage" "$production" 'internal/app/' &&
        diff -u "$expected" "$coverage"
}

out_of_package_lines_are_not_merged() {
    local coverage="$work_dir/filter-coverage.out"
    local production="$work_dir/filter-production.out"

    printf 'mode: set\nexample.com/signer/internal/app/app.go:1.1,2.2 1 1\n' >"$coverage"
    cat >"$production" <<'EOF'
mode: set
example.com/signer/internal/app/runtime_prod.go:1.1,2.2 1 1
example.com/signer/internal/enclave/enclave.go:1.1,2.2 1 1
EOF

    merge "$coverage" "$production" 'internal/app/' &&
        grep -Fq 'internal/app/runtime_prod.go' "$coverage" &&
        ! grep -Fq 'internal/enclave/enclave.go' "$coverage"
}

package_prefix_without_trailing_slash_is_anchored() {
    local coverage="$work_dir/prefix-coverage.out"
    local production="$work_dir/prefix-production.out"

    printf 'mode: set\nexample.com/signer/internal/common/config.go:1.1,2.2 1 1\n' >"$coverage"
    cat >"$production" <<'EOF'
mode: set
example.com/signer/internal/app/runtime_prod.go:1.1,2.2 1 1
example.com/signer/internal/appconfig/config.go:1.1,2.2 1 1
EOF

    merge "$coverage" "$production" 'internal/app' &&
        grep -Fq 'internal/app/runtime_prod.go' "$coverage" &&
        ! grep -Fq 'internal/appconfig/config.go' "$coverage"
}

same_profile_path_is_rejected() {
    local profile="$work_dir/same-profile.out"

    printf 'mode: set\nexample.com/signer/internal/app/app.go:1.1,2.2 1 1\n' >"$profile"

    fails_with 'PROFILE_PATHS_MATCH' \
        merge "$profile" "$profile" 'internal/app/'
}

production_profile_without_package_is_rejected() {
    local coverage="$work_dir/package-coverage.out"
    local production="$work_dir/package-production.out"

    printf 'mode: set\nexample.com/signer/internal/app/app.go:1.1,2.2 1 1\n' >"$coverage"
    printf 'mode: set\nexample.com/signer/internal/enclave/enclave.go:1.1,2.2 1 1\n' >"$production"

    fails_with 'PACKAGE_COVERAGE_MISSING' \
        merge "$coverage" "$production" 'internal/app/'
}

check 'The merge identifies each missing or empty argument.' missing_or_empty_arguments_are_rejected
check 'The merge adds new production files.' new_production_files_are_merged
check 'The merge rejects different coverage modes.' coverage_mode_mismatch_is_rejected
check 'The merge identifies the base profile path for an invalid mode header.' missing_mode_header_is_rejected
check 'The merge identifies the production profile path for an invalid mode header.' production_missing_mode_header_is_rejected
check 'The merge rejects a missing production profile.' missing_production_profile_is_rejected
check 'The merge rejects an empty base profile.' empty_base_profile_is_rejected
unreadable_profile_description='The merge identifies each unreadable profile path.'
if [ "$(id -u)" -eq 0 ]; then
    skip_check "$unreadable_profile_description" \
        'Root can read files without read permission.'
else
    check "$unreadable_profile_description" unreadable_profiles_are_rejected
fi
check 'The base profile does not change after an AWK error.' awk_fatal_error_preserves_base_profile
check 'The merge removes temporary profiles after an AWK error.' awk_fatal_error_removes_temp_profiles
check 'The first temporary profile error has a stable identifier.' first_temp_profile_failure_uses_stable_diagnostic
check 'The second temporary profile error removes the first temporary profile.' second_temp_profile_failure_removes_first_temp_profile
check 'The merge identifies a merged profile write error and preserves the base profile.' \
    final_profile_command_failure_uses_stable_diagnostic cat MERGED_PROFILE_WRITE_FAILED
check 'The merge identifies a base profile replace error and preserves the base profile.' \
    final_profile_command_failure_uses_stable_diagnostic mv BASE_PROFILE_REPLACE_FAILED
check 'The merge accepts a profile with no new files.' zero_additions_is_allowed
check 'The merge does not include files from other packages.' out_of_package_lines_are_not_merged
check 'The merge accepts a package prefix without a trailing slash.' package_prefix_without_trailing_slash_is_anchored
check 'The merge rejects the same path for both profiles.' same_profile_path_is_rejected
check 'The production profile must contain package coverage.' production_profile_without_package_is_rejected

exit "$failures"
