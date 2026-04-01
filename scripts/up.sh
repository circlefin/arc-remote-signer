#!/usr/bin/env bash

# up.sh starts the supporting infrastructure in local-dev

BASE_DIR="$(dirname "$0")"
. "${BASE_DIR}/common.sh"

# Pull latest container images.
if [[ "${PULL_IMAGES:-false}" = true ]] ; then
    echo 'Pulling latest container images from ECR.'
    docker-compose -f "${PROJECT_DIR}/deployments/docker-compose.yaml" pull
fi

if [ "${USE_LOCALSTACK:-false}" = "true" ]; then
    if [ "${PULL_IMAGES:-false}" = "true" ]; then
      echo 'Pulling latest container images from ECR for localstack.'
      docker-compose -f "${PROJECT_DIR}/deployments/docker-compose.yaml" pull localstack
    fi

    ## Start localstack container
    docker-compose -f "${PROJECT_DIR}/deployments/docker-compose.yaml" up -d localstack
fi

if [[ "${DOCKER_UP:-true}" = true ]] ; then
  time docker-compose -f "${PROJECT_DIR}/deployments/docker-compose.yaml" up --wait && true
  exit_code=$?
  if [[ "$exit_code" -eq 1 ]]; then
    . "${BASE_DIR}/export-container-logs.sh"
    echo "exit on code ${exit_code}, container startup failed"
    exit $exit_code
  fi
fi
