#!/usr/bin/env bash

# smoke.sh runs smoke tests for the app service.

BASE_DIR="$(dirname "$0")"
. "${BASE_DIR}/common.sh"

cd "$PROJECT_DIR" || exit

trap '. "${BASE_DIR}/export-container-logs.sh"; . "${BASE_DIR}/down.sh"' EXIT

stop_app() {
  if [ -e "${PROJECT_DIR}/app.pid" ]
  then
    local app_pid
    IFS= read -r app_pid < "${PROJECT_DIR}/app.pid"
    if ps -p "$app_pid" > /dev/null
    then
      kill "$app_pid"
      wait "$app_pid" 2> /dev/null || true
      for ((attempt = 0; attempt < 50; attempt++))
      do
        if ! ps -p "$app_pid" > /dev/null
        then
          return 0
        fi
        sleep 0.1
      done
      echo 'The app did not stop.' >&2
      return 1
    fi
  fi
}

start_app() {
  local app_pid
  if ! stop_app
  then
    echo 'The previous app instance did not stop.' >&2
    return 1
  fi
  AWS_REGION=us-east-1 "${BIN_DIR}/app" --config "${PROJECT_DIR}/configs/app.yaml" run &
  app_pid=$!
  echo "$app_pid" > "${PROJECT_DIR}/app.pid"
  sleep 5
  kill -0 "$app_pid"
}

start_app

go test -tags=smoke -count=1 "${PROJECT_DIR}/..." && true
exit_code=$?

if [ "$exit_code" -eq 0 ]
then
  go test -tags=smoke -run '^TestPublicV2$' -count=1 \
    "${PROJECT_DIR}/internal/smoke/public" && true
  exit_code=$?
fi

if [ "$exit_code" -eq 0 ]
then
  start_app
  SMOKE_VERIFY_RESTART=true go test \
    -tags=smoke \
    -run '^TestPublicV2$' \
    -count=1 \
    "${PROJECT_DIR}/internal/smoke/public" && true
  exit_code=$?
fi

echo "exit on code ${exit_code}"
exit $exit_code
