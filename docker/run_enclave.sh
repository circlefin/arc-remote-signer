#!/usr/bin/env bash

set -eu

# Discard all output. Network setup failures are silent by design.
exec >/dev/null 2>&1

ip addr add 127.0.0.1/32 dev lo
ip link set dev lo up

exec env APP_PUBLIC_SERVER_PORT=10350 \
    /usr/local/circle/enclave \
    --enclave-config /usr/local/circle/configs/enclave.yaml
