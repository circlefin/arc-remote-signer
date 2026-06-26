ARG GO_IMAGE=golang:1.25@sha256:00feed335fe561979f2cdcc30a5191231977c5631fe79c40f7d3ab63b4fa222f
ARG RUST_IMAGE=rust:1.95-bookworm@sha256:adab7941580c74513aa3347f2d2a1f975498280743d29ec62978ba12e3540d3a
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716
ARG NITRO_CLI_VERSION=v1.4.4
# SHA256 of the source tarball for ${NITRO_CLI_VERSION}. Verified at build
# time so a retagged upstream cannot silently change the binary we ship.
ARG NITRO_CLI_SHA256=5f8182119496a07403b755e1c7e62780acc71ba136639226cdbb508482836e01

### Build the application binary.
FROM ${GO_IMAGE} AS app-builder

ARG TARGETARCH

RUN --mount=type=bind,from=certs,target=/usr/local/share/ca-certificates/ \
    update-ca-certificates && \
    go install github.com/bufbuild/buf/cmd/buf@v1.50.0 && \
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
WORKDIR /src/proto
RUN buf generate
WORKDIR /src
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -o /out/app .

### Build grpc-health-probe from master (404552c) to get grpc v1.79.3 (CVE-2026-33186 fix).
### TODO: Revert to `COPY --from=ghcr.io/grpc-ecosystem/grpc-health-probe:<tag>` once a tagged release includes grpc >= v1.79.3.
FROM ${GO_IMAGE} AS grpc-health-probe-builder

RUN --mount=type=bind,from=certs,target=/usr/local/share/ca-certificates/ \
    update-ca-certificates && \
    CGO_ENABLED=0 GOBIN=/ go install github.com/grpc-ecosystem/grpc-health-probe@404552c

### Build nitro-cli from source. Only the binary is needed at runtime; blobs
### are only used when building EIFs (handled by the shared CI pipeline).
FROM ${RUST_IMAGE} AS nitro-cli-builder

ARG NITRO_CLI_VERSION
ARG NITRO_CLI_SHA256

RUN --mount=type=bind,from=certs,target=/usr/local/share/ca-certificates/ \
    update-ca-certificates && \
    apt-get update && \
    apt-get install -y --no-install-recommends musl-tools && \
    rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -sSfL -o /tmp/nitro-cli.tar.gz \
        "https://github.com/aws/aws-nitro-enclaves-cli/archive/refs/tags/${NITRO_CLI_VERSION}.tar.gz" && \
    echo "${NITRO_CLI_SHA256}  /tmp/nitro-cli.tar.gz" | sha256sum -c - && \
    tar xzf /tmp/nitro-cli.tar.gz --strip-components=1 && \
    rm /tmp/nitro-cli.tar.gz && \
    make nitro-cli-native && \
    install -D -m 0755 build/nitro_cli/release/nitro-cli /out/usr/bin/nitro-cli && \
    mkdir -p /out/var/log/nitro_enclaves /out/run/nitro_enclaves

### This is the base image that all other images inherit from
FROM ${DEBIAN_IMAGE} AS base

ARG TARGETARCH

WORKDIR /usr/local/circle

COPY --from=app-builder --chmod=0750 /out/app ./app
COPY configs ./configs
COPY deployments ./deployments

## Copy CA certs from the builder so apt trusts the configured CA bundle
## (e.g. when the build runs behind a proxy with a custom root CA).
COPY --from=grpc-health-probe-builder /etc/ssl/certs /etc/ssl/certs

## Install common dependencies for all targets
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        socat \
        jq && \
    rm -rf /var/lib/apt/lists/*

COPY --from=grpc-health-probe-builder /grpc-health-probe /usr/local/bin/grpc_health_probe

### This is the image that runs outside the nitro enclave, but does not include the enclave binary (EIF file)
FROM base AS signer

COPY --chmod=0750 docker/run_proxy.sh ./run_proxy.sh
COPY --chmod=0750 docker/run_enclave.sh ./run_enclave.sh
COPY --chmod=0750 docker/run_enclave.dev.sh ./run_enclave.dev.sh
ENTRYPOINT ["/usr/local/circle/run_proxy.sh"]

### This is the image that runs outside the nitro enclave, including the enclave binary (EIF file)
FROM signer AS signer-with-enclave

ARG ENCLAVE_EIF
ARG ENCLAVE_PCR0=""
ARG ENCLAVE_PCR1=""
ARG ENCLAVE_PCR2=""

LABEL enclave.pcr0="${ENCLAVE_PCR0}" \
      enclave.pcr1="${ENCLAVE_PCR1}" \
      enclave.pcr2="${ENCLAVE_PCR2}"

COPY --from=nitro-cli-builder /out/ /

COPY $ENCLAVE_EIF ./enclave.eif

COPY --chmod=0750 docker/run.sh ./run.sh
ENTRYPOINT ["/usr/local/circle/run.sh"]
