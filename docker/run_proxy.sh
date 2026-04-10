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

exec env AWS_REGION=us-east-1 APP_PUBLIC_SERVER_PORT=10340 /usr/local/circle/app --config /usr/local/circle/configs/app.yaml run
