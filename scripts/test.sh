#!/usr/bin/env bash

# test.sh runs linting and tests for the app. Set the env var RUN_IT_TESTS to run the integration tests.

BASE_DIR="$(dirname "$0")"
. "${BASE_DIR}/common.sh"

cd "$PROJECT_DIR" || exit

bash "${BASE_DIR}/test-ci-shell.sh"
bash "${BASE_DIR}/test-dev-image.sh"
bash "${BASE_DIR}/test-production-image.sh"
bash "${BASE_DIR}/test-production-coverage.sh"
bash "${BASE_DIR}/test-secure-eif.sh"

# shellcheck disable=SC2039
case $OSTYPE in
  linux* )
    PLATFORM="linux";;
  darwin* )
    PLATFORM="darwin";;
  *)
    echo "Unknown ostype $OSTYPE"
    exit 1;;
esac

ARCH_CHECK="$(uname -m)"  # -i is only linux, -m is linux and apple
if [[ "$ARCH_CHECK" = x86_64* ]]; then
  ARCH="amd64"
else
  ARCH="arm64"
fi

GOLANGCI_LINT_VERSION="2.11.4"
MOCKGEN_VERSION="1.6.0"
GO_JUNIT_REPORT_VERSION="2.0.0"
GO_IGNORE_COV_VERSION="0.4.0"

# Install tools
if ! command -v golangci-lint || [[ "$(golangci-lint version --short)" != "v$GOLANGCI_LINT_VERSION" ]]; then
  echo "golangci-lint is either not installed or installed a wrong version. Installing version $GOLANGCI_LINT_VERSION."
  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v${GOLANGCI_LINT_VERSION}
fi
if ! command -v mockgen || [[ "$(mockgen -version)" != "v$MOCKGEN_VERSION" ]]; then
  echo "mockgen is either not installed or installed a wrong version. Installing version $MOCKGEN_VERSION."
  go install github.com/golang/mock/mockgen@v${MOCKGEN_VERSION}
fi
if ! command -v go-junit-report || [[ "$(go-junit-report -version | awk '{print $2}' | cut -d "-" -f 1)" != "v$GO_JUNIT_REPORT_VERSION" ]]; then
  echo "mockgen is either not installed or installed a wrong version. Installing version $GO_JUNIT_REPORT_VERSION."
  go install github.com/jstemmer/go-junit-report/v2@v${GO_JUNIT_REPORT_VERSION}
fi
if ! command -v go-ignore-cov; then
  go install github.com/quantumcycle/go-ignore-cov@v${GO_IGNORE_COV_VERSION} # go lang coverage ignore tool
fi

# Generate mocks
go generate "${PROJECT_DIR}/..."

# Setup coverage
COVERAGE_DIR=coverage
mkdir -p ${COVERAGE_DIR}

TEST_RESULTS_DIR=test_results
mkdir -p ${TEST_RESULTS_DIR}

golangci-lint run --config "${PROJECT_DIR}/build/golangci.yaml"
# Run a separate lint pass for the production build tag.
if [ "$PLATFORM" = "linux" ]; then
  golangci-lint run --config "${PROJECT_DIR}/build/golangci.yaml" \
    --build-tags=prod "${PROJECT_DIR}/..."
else
  golangci-lint run --config "${PROJECT_DIR}/build/golangci.yaml" \
    --build-tags=prod \
    "${PROJECT_DIR}/internal/app/..." \
    "${PROJECT_DIR}/internal/vsockproxy/..." \
    "${PROJECT_DIR}/cmd/..."
fi

if [ "${RUN_IT_TESTS:-false}" = true ]; then
  # count=1 ensures tests are not cached; helpful if making non src code changes that may affect the test.
  # Add -coverpkg for integration tests to ensure coverage is properly computed.
  go test -tags=integration -count=1 -coverpkg=./... -coverprofile="${COVERAGE_DIR}/integration_raw.out" "${PROJECT_DIR}/..." -v 2>&1 | tee /dev/stderr | go-junit-report -set-exit-code -out ${TEST_RESULTS_DIR}/unit-integration-tests-report.xml && true
  exit_code=$?
  cp "${COVERAGE_DIR}/integration_raw.out" "${COVERAGE_DIR}/coverage.out"
else
  go test -coverprofile="${COVERAGE_DIR}/unit_raw.out" "${PROJECT_DIR}/..."
  exit_code=$?
  cp "${COVERAGE_DIR}/unit_raw.out" "${COVERAGE_DIR}/coverage.out"
fi

if [ $exit_code -ne 0 ]; then
  . "${BASE_DIR}/export-container-logs.sh"
  echo "exit on code ${exit_code}"
  exit $exit_code
fi

# Production app files use a mutually exclusive build tag. Add files that are
# present only in the production package to the default profile.
prod_exit=0
go test -tags=prod -coverprofile="${COVERAGE_DIR}/prod_raw.out" "${PROJECT_DIR}/internal/app" || prod_exit=$?
go test -tags=prod "${PROJECT_DIR}/internal/vsockproxy" "${PROJECT_DIR}/internal/enclave" || prod_exit=$?
CGO_ENABLED=0 go test -tags=prod "${PROJECT_DIR}/cmd/enclave" || prod_exit=$?
if [ $prod_exit -ne 0 ]; then
  echo "Production tests failed with exit code ${prod_exit}."
  exit $prod_exit
fi
bash "${BASE_DIR}/merge-production-coverage.sh" \
  "${COVERAGE_DIR}/coverage.out" \
  "${COVERAGE_DIR}/prod_raw.out" \
  'internal/app/'

# Run go-ignore-cov to process coverage ignore post processing
# If no coverage to ignore, there are no changes to the coverage file.
go-ignore-cov --file "${COVERAGE_DIR}/coverage.out" --output "${COVERAGE_DIR}/coverage.out" --root "${PROJECT_DIR}"
