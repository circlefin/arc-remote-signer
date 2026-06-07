#!/usr/bin/env bash

# down.sh tears down the local environment

BASE_DIR="$(dirname "$0")"
. "${BASE_DIR}/common.sh"

if [ -e "${PROJECT_DIR}/app.pid" ]
then
  < "${PROJECT_DIR}/app.pid" xargs kill || true
fi

if [ "${USE_LOCALSTACK:-false}" = "true" ]; then
    ## Stop localstack container
    docker compose -f "${PROJECT_DIR}/deployments/docker-compose.yaml" down localstack
fi

docker compose -f "${PROJECT_DIR}/deployments/docker-compose.yaml" down --remove-orphans
