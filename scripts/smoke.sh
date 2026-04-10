#!/usr/bin/env bash

# smoke.sh runs smoke tests for the app service.

BASE_DIR="$(dirname "$0")"
. "${BASE_DIR}/common.sh"

cd "$PROJECT_DIR" || exit

if [ -e app.pid ]
then
  if < "${PROJECT_DIR}/app.pid" xargs ps -p > /dev/null
  then
    < "${PROJECT_DIR}/app.pid" xargs kill
  fi
fi
AWS_REGION=us-east-1 "${BIN_DIR}/app" --config "${PROJECT_DIR}/configs/app.yaml" run &
echo $! > "${PROJECT_DIR}/app.pid"

sleep 5

go test -tags=smoke -count=1 "${PROJECT_DIR}/..." && true
exit_code=$?

. "${BASE_DIR}/export-container-logs.sh"
. "${BASE_DIR}/down.sh"
echo "exit on code ${exit_code}"
exit $exit_code
