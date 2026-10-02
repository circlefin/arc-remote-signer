#!/usr/bin/env bash

set -eu

exec /usr/local/circle/app \
    --config /usr/local/circle/config.yaml \
    run
