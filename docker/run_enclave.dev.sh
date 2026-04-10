#!/usr/bin/env bash

set -eux

PROJECT_DIR="$(dirname "$0")/.."
BIN_DIR="${PROJECT_DIR}/bin"
CMD_DIR="${PROJECT_DIR}/cmd"

export PROJECT_DIR
export BIN_DIR
export CMD_DIR

mkdir -p /usr/local/circle/logs
touch /usr/local/circle/logs/app.log

exec env APP_PUBLIC_SERVER_PORT=10350 /usr/local/circle/app --enclave-config /usr/local/circle/configs/enclave.yaml run-enclave
