#!/usr/bin/env bash

# dev.sh starts the app in local dev.

BASE_DIR="$(dirname "$0")"
. "${BASE_DIR}/common.sh"

# setup logging directory
 mkdir -p "${PROJECT_DIR}/logs"

AWS_REGION=us-east-1 APP_PUBLIC_SERVER_PORT=10340 "${BIN_DIR}/app" --config "${PROJECT_DIR}/configs/app.yaml" run
