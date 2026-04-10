#!/usr/bin/env bash

# common.sh sets good shell defaults and exports helpful environment variables.
# All scripts should start by sourcing this script:
#   BASE_DIR="$(dirname "$0")"
#   . "${BASE_DIR}/common.sh"

# -e exits on error, -u errors on undefined variables, -x sets tracing mode
set -eux

get_abs_filename() {
  # $1 : relative filename
  echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
}
# Basic project paths
export PROJECT_DIR=$(get_abs_filename "$(dirname "$0")/..")
export BIN_DIR="${PROJECT_DIR}/bin"

# Environment configuration
export APP_ENV=${APP_ENV:-"dev"}

# Gets all the development environment variables
set -o allexport && source "${PROJECT_DIR}/configs/.env.dev" && set +o allexport
