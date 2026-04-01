### Build grpc-health-probe from master (404552c) to get grpc v1.79.3 (CVE-2026-33186 fix).
### TODO: Revert to `COPY --from=ghcr.io/grpc-ecosystem/grpc-health-probe:<tag>` once a tagged release includes grpc >= v1.79.3.
FROM golang:1.25 AS grpc-health-probe-builder
RUN CGO_ENABLED=0 GOBIN=/ go install github.com/grpc-ecosystem/grpc-health-probe@404552c

### This is the base image that all other images inherit from
FROM ubuntu:22.04 AS base

ARG TARGETARCH

WORKDIR /usr/local/circle

COPY --chmod=0750 bin/$TARGETARCH/app ./app
COPY configs ./configs
COPY deployments ./deployments

## Install common dependencies for all targets
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        socat \
        jq && \
    rm -rf /var/lib/apt/lists/*

COPY --from=grpc-health-probe-builder /grpc-health-probe /usr/local/bin/grpc_health_probe

### This is the image that runs in the nitro enclave
FROM base AS enclave

## Install network configuration tools needed only in the enclave
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 && \
    rm -rf /var/lib/apt/lists/*

COPY --chmod=0750 docker/run_enclave.sh ./run_enclave.sh
ENTRYPOINT ["/usr/local/circle/run_enclave.sh"]

### This is the image that runs outside the nitro enclave, but does not include the enclave binary (EIF file)
FROM base AS signer

COPY --chmod=0750 docker/run_proxy.sh ./run_proxy.sh
COPY --chmod=0750 docker/run_enclave.sh ./run_enclave.sh
COPY --chmod=0750 docker/run_enclave.dev.sh ./run_enclave.dev.sh
ENTRYPOINT ["/usr/local/circle/run_proxy.sh"]

### This is the image that runs outside the nitro enclave, including the enclave binary (EIF file)
FROM signer AS signer-with-enclave

ARG ENCLAVE_EIF

COPY $ENCLAVE_EIF ./enclave.eif

COPY --chmod=0750 docker/run.sh ./run.sh
ENTRYPOINT ["/usr/local/circle/run.sh"]
