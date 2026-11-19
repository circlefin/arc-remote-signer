#!/bin/sh

set -eu

for attempt in 1 2 3; do
    rm -rf /var/lib/apt/lists/*
    printf 'Enclave runtime package install attempt %s of 3.\n' "$attempt" >&2
    # Bound network acquisition without interrupting dpkg configuration.
    if timeout --verbose --kill-after=5s 240s sh -c '
        apt-get -o Acquire::Retries=10 \
            -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 \
            update --error-on=any &&
        apt-get -o Acquire::Retries=10 \
            -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 \
            --download-only install -y --no-install-recommends iproute2 ca-certificates
    ' &&
        apt-get --no-download install -y --no-install-recommends iproute2 ca-certificates; then
        exit 0
    fi
    printf 'Enclave runtime package install failed on attempt %s of 3.\n' "$attempt" >&2
    if [ "$attempt" -eq 3 ]; then
        exit 1
    fi
    sleep "$((attempt * 10))"
done
