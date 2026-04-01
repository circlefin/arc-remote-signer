#!/usr/bin/env bash

# build.sh builds the app binaries.

BASE_DIR="$(dirname "$0")"
. "${BASE_DIR}/common.sh"

go mod tidy
go mod download

cd "${PROJECT_DIR}/proto"
make lint
make proto

if [ $APP_ENV == "qa" ];
then
    ## build command reference: https://github.com/supranational/blst/blob/master/bindings/go/README.md#caveats
    GOOS=linux GOARCH=amd64 CGO_ENABLED=1 CGO_CFLAGS="-O2 -D__BLST_PORTABLE__" go build -o "${BIN_DIR}/amd64/app" "${PROJECT_DIR}"
    cp ${BIN_DIR}/amd64/app ${BIN_DIR}/
else
    CURRENT_OS=$(uname -s)
    if [ "$CURRENT_OS" = "Darwin" ]; then
        ## install aarch64-linux-gnu, first run requires installation which takes longer time
        ## can be changed to use docker for build in the future
        brew tap messense/macos-cross-toolchains
        brew install aarch64-unknown-linux-gnu
        GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 go build -o "${BIN_DIR}/arm64/app" "${PROJECT_DIR}"
    fi

    go build -o "${BIN_DIR}/app" "${PROJECT_DIR}"
fi
