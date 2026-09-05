#!/usr/bin/env bash

set -eux

mkdir -p /usr/local/circle/logs
touch /usr/local/circle/logs/app.log

exec env APP_PUBLIC_SERVER_PORT=10350 /usr/local/circle/enclave --enclave-config /usr/local/circle/configs/enclave.yaml
