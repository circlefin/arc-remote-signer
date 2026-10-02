#!/usr/bin/env bash

set -eu

# Use this command:
# merge-production-coverage.sh BASE_PROFILE PRODUCTION_PROFILE PACKAGE_PREFIX
#
# PACKAGE_PREFIX is a source-directory suffix, such as internal/app.
# You can use PACKAGE_PREFIX with or without a trailing slash.
# The command rejects the same path for both profiles.
# The command rejects missing, empty, or malformed profiles.
# The command also rejects unreadable profiles.
# The command also rejects a production profile without PACKAGE_PREFIX coverage.
# Both profiles must use the same coverage mode.
# The command changes BASE_PROFILE in place only after a successful merge.
# BASE_PROFILE keeps its coverage for files in both profiles.
# The command adds production-only files below PACKAGE_PREFIX to BASE_PROFILE.
# Each error starts with a stable diagnostic identifier.
# The brackets contain context. The context format is not stable.
# Only the identifier is stable.

report_error() {
    local identifier="$1"
    local context="$2"
    local message="$3"

    printf '%s [%s]: %s\n' "$identifier" "$context" "$message" >&2
}

if [ -z "${1:-}" ]; then
    report_error 'MISSING_ARGUMENT' 'BASE_PROFILE' \
        'Give the path to the base coverage profile.'
    exit 1
fi
if [ -z "${2:-}" ]; then
    report_error 'MISSING_ARGUMENT' 'PRODUCTION_PROFILE' \
        'Give the path to the production coverage profile.'
    exit 1
fi
if [ -z "${3:-}" ]; then
    report_error 'MISSING_ARGUMENT' 'PACKAGE_PREFIX' \
        'Give the package prefix.'
    exit 1
fi

coverage="$1"
production="$2"
package_prefix="${3%/}/"

if [ "$coverage" = "$production" ]; then
    report_error 'PROFILE_PATHS_MATCH' "$coverage" \
        'The base and production profiles must use different paths.'
    exit 1
fi

if [ ! -s "$coverage" ]; then
    report_error 'BASE_PROFILE_MISSING_OR_EMPTY' "$coverage" \
        'The base coverage profile is missing or empty.'
    exit 1
fi
if [ ! -s "$production" ]; then
    report_error 'PRODUCTION_PROFILE_MISSING_OR_EMPTY' "$production" \
        'The production coverage profile is missing or empty.'
    exit 1
fi
if [ ! -r "$coverage" ]; then
    report_error 'BASE_PROFILE_UNREADABLE' "$coverage" \
        'The process cannot read the base coverage profile.'
    exit 1
fi
if [ ! -r "$production" ]; then
    report_error 'PRODUCTION_PROFILE_UNREADABLE' "$production" \
        'The process cannot read the production coverage profile.'
    exit 1
fi

coverage_mode="$(sed -n '1p' "$coverage")"
production_mode="$(sed -n '1p' "$production")"

validate_mode_header() {
    local profile="$1"
    local mode="$2"

    case "$mode" in
        'mode: set' | 'mode: count' | 'mode: atomic') ;;
        *)
            report_error 'INVALID_MODE_HEADER' "$profile" \
                "The profile has an invalid mode header: $mode"
            exit 1
            ;;
    esac
}

validate_mode_header "$coverage" "$coverage_mode"
validate_mode_header "$production" "$production_mode"

if [ "$coverage_mode" != "$production_mode" ]; then
    report_error 'COVERAGE_MODE_MISMATCH' "$coverage | $production" \
        "The profiles use different coverage modes: $coverage_mode and $production_mode."
    exit 1
fi

additions=''
merged=''
additions_template="${coverage}.additions.XXXXXX"
merged_template="${coverage}.merged.XXXXXX"

remove_temp_profiles() {
    if [ -n "$additions" ]; then
        rm -f "$additions"
    fi
    if [ -n "$merged" ]; then
        rm -f "$merged"
    fi
}

trap remove_temp_profiles EXIT

if ! additions="$(mktemp "$additions_template")"; then
    report_error 'TEMP_PROFILE_CREATE_FAILED' "$additions_template" \
        'The command cannot create a temporary coverage profile.'
    exit 1
fi
if ! merged="$(mktemp "$merged_template")"; then
    report_error 'TEMP_PROFILE_CREATE_FAILED' "$merged_template" \
        'The command cannot create a temporary coverage profile.'
    exit 1
fi

merge_status=0
awk -v package_prefix="$package_prefix" '
    function source_file(line, fields, source) {
        split(line, fields, " ")
        source = fields[1]
        sub(/:[0-9].*$/, "", source)
        return source
    }

    function in_package(source) {
        return index(source, package_prefix) == 1 ||
            index(source, "/" package_prefix) > 0
    }

    FNR == 1 { next }

    FILENAME == ARGV[1] {
        existing[source_file($0)] = 1
        next
    }

    {
        source = source_file($0)
        if (in_package(source)) {
            found_package = 1
            if (!(source in existing)) {
                print
            }
        }
    }

    END {
        if (!found_package) {
            exit 3
        }
    }
' "$coverage" "$production" >"$additions" || merge_status=$?
case "$merge_status" in
    0) ;;
    3)
        report_error 'PACKAGE_COVERAGE_MISSING' "$production" \
            "The production profile does not contain coverage for $package_prefix."
        exit 1
        ;;
    *)
        report_error 'COVERAGE_MERGE_FAILED' "$production -> $coverage" \
            'The command cannot merge the production profile into the base profile.'
        exit 1
        ;;
esac

if ! cat "$coverage" "$additions" >"$merged"; then
    report_error 'MERGED_PROFILE_WRITE_FAILED' "$merged" \
        'The command cannot write the merged coverage profile.'
    exit 1
fi
if ! mv "$merged" "$coverage"; then
    report_error 'BASE_PROFILE_REPLACE_FAILED' "$merged -> $coverage" \
        'The command cannot replace the base coverage profile.'
    exit 1
fi
