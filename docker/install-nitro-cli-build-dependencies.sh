#!/bin/sh

set -eu

for attempt in 1 2 3; do
    rm -rf /var/lib/apt/lists/*
    if apt-get -o Acquire::Retries=3 update --error-on=any &&
        apt-get -o Acquire::Retries=3 install -y --no-install-recommends musl-tools; then
        rm -rf /var/lib/apt/lists/*
        exit 0
    fi
    if [ "$attempt" -eq 3 ]; then
        exit 1
    fi
    sleep "$((attempt * 10))"
done
