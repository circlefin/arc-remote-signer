#!/usr/bin/env bash

# This file contains the common shell test result functions.
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

skip_check() {
    local description="$1"
    local reason="$2"

    printf 'skip - %s %s\n' "$description" "$reason"
}
