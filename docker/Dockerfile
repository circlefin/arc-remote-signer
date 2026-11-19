ARG GO_IMAGE=golang:1.26.10@sha256:cfa27959837144bf4649802ba38e59daffd0dd2a7994aa83daaf113285b0f551
ARG RUST_IMAGE=rust:1.95-bookworm@sha256:adab7941580c74513aa3347f2d2a1f975498280743d29ec62978ba12e3540d3a
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716
ARG NITRO_CLI_VERSION=v1.4.4
# SHA256 of the source tarball for ${NITRO_CLI_VERSION}. Verified at build
# time so a retagged upstream cannot silently change the binary we ship.
ARG NITRO_CLI_SHA256=5f8182119496a07403b755e1c7e62780acc71ba136639226cdbb508482836e01

### Build the application binary.
FROM ${GO_IMAGE} AS app-builder

ARG TARGETARCH
ARG CLOUDSMITH_USER
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOAUTH=netrc \
    GOPROXY=${GOPROXY} \
    GONOPROXY=none \
    GONOSUMDB=github.com/circlefin/*

RUN --mount=type=bind,from=certs,target=/usr/local/share/ca-certificates/ \
    --mount=type=bind,source=docker/go-with-proxy.sh,target=/tmp/go-with-proxy.sh \
    --mount=type=secret,id=cloudsmith_token,env=CLOUDSMITH_TOKEN \
    update-ca-certificates && \
    sh /tmp/go-with-proxy.sh sh -eu -c 'GOTOOLCHAIN=go1.26.10 go install github.com/bufbuild/buf/cmd/buf@v1.75.0 && \
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1'

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=bind,source=docker/go-with-proxy.sh,target=/tmp/go-with-proxy.sh \
    --mount=type=secret,id=cloudsmith_token,env=CLOUDSMITH_TOKEN \
    sh /tmp/go-with-proxy.sh go mod download

COPY . .
WORKDIR /src/proto
RUN buf generate
WORKDIR /src
RUN export CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} && \
    go build -o /out/app . && \
    go build -o /out/enclave ./cmd/enclave && \
    go build -tags=prod -o /out/app-production .

### Build grpc-health-probe from master (404552c) to get grpc v1.79.3 (CVE-2026-33186 fix).
### TODO: Revert to `COPY --from=ghcr.io/grpc-ecosystem/grpc-health-probe:<tag>` once a tagged release includes grpc >= v1.79.3.
FROM ${GO_IMAGE} AS grpc-health-probe-builder

ARG CLOUDSMITH_USER
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOAUTH=netrc \
    GOPROXY=${GOPROXY} \
    GONOPROXY=none \
    GONOSUMDB=github.com/circlefin/*

RUN --mount=type=bind,from=certs,target=/usr/local/share/ca-certificates/ \
    --mount=type=bind,source=docker/go-with-proxy.sh,target=/tmp/go-with-proxy.sh \
    --mount=type=secret,id=cloudsmith_token,env=CLOUDSMITH_TOKEN \
    update-ca-certificates && \
    CGO_ENABLED=0 GOBIN=/ sh /tmp/go-with-proxy.sh go install github.com/grpc-ecosystem/grpc-health-probe@404552c

### Build nitro-cli from source. Only the binary is needed at runtime; blobs
### are only used when building EIFs (handled by the shared CI pipeline).
FROM ${RUST_IMAGE} AS nitro-cli-builder

ARG NITRO_CLI_VERSION
ARG NITRO_CLI_SHA256

COPY --chmod=0755 docker/install-nitro-cli-build-dependencies.sh /usr/local/bin/
RUN --mount=type=bind,from=certs,target=/usr/local/share/ca-certificates/ \
    update-ca-certificates && \
    /usr/local/bin/install-nitro-cli-build-dependencies.sh

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -sSfL -o /tmp/nitro-cli.tar.gz \
        "https://github.com/aws/aws-nitro-enclaves-cli/archive/refs/tags/${NITRO_CLI_VERSION}.tar.gz" && \
    echo "${NITRO_CLI_SHA256}  /tmp/nitro-cli.tar.gz" | sha256sum -c - && \
    tar xzf /tmp/nitro-cli.tar.gz --strip-components=1 && \
    rm /tmp/nitro-cli.tar.gz && \
    make nitro-cli-native && \
    install -D -m 0755 build/nitro_cli/release/nitro-cli /out/usr/bin/nitro-cli && \
    mkdir -p /out/var/log/nitro_enclaves /out/run/nitro_enclaves

### Runtime files shared by production and development images.
FROM ${DEBIAN_IMAGE} AS runtime-base

WORKDIR /usr/local/circle

# Use the builder CA bundle when the build uses a custom root CA.
COPY --from=grpc-health-probe-builder /etc/ssl/certs /etc/ssl/certs
COPY --from=grpc-health-probe-builder /grpc-health-probe /usr/local/bin/grpc_health_probe

### Runtime files shared by the production signer images.
FROM runtime-base AS production-runtime

COPY --from=app-builder --chmod=0750 /out/app-production ./app
COPY configs/app.production.yaml ./config.yaml

### The signer image runs a production host with an external Nitro enclave.
FROM production-runtime AS signer

COPY --chmod=0750 docker/run_proxy.production.sh ./run_proxy.sh
ENTRYPOINT ["/usr/local/circle/run_proxy.sh"]

### The signer-dev image runs the host and enclave processes without a Nitro EIF.
FROM runtime-base AS signer-dev

COPY --from=app-builder --chmod=0750 /out/app ./app
COPY --from=app-builder --chmod=0750 /out/enclave ./enclave
COPY configs ./configs
COPY deployments ./deployments
COPY --chmod=0750 docker/run_proxy.sh ./run_proxy.sh
COPY --chmod=0750 docker/run_enclave.dev.sh ./run_enclave.dev.sh
ENTRYPOINT ["/usr/local/circle/run_proxy.sh"]

### The signer-with-enclave image includes the production EIF.
FROM production-runtime AS signer-with-enclave

ARG ENCLAVE_EIF
ARG ENCLAVE_PCR0=""
ARG ENCLAVE_PCR1=""
ARG ENCLAVE_PCR2=""

LABEL enclave.pcr0="${ENCLAVE_PCR0}" \
      enclave.pcr1="${ENCLAVE_PCR1}" \
      enclave.pcr2="${ENCLAVE_PCR2}"

COPY --from=nitro-cli-builder /out/ /

# bookworm-slim ships perl-base 5.36.0-7+deb12u3. Upgrade it so the image
# picks up deb12u4 (CVE-2026-13221, CVE-2026-42496, CVE-2026-8376).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        jq \
        libssl3 \
        perl-base && \
    rm -rf /var/lib/apt/lists/*

COPY $ENCLAVE_EIF ./enclave.eif

COPY --chmod=0750 docker/run.sh ./run.sh
ENTRYPOINT ["/usr/local/circle/run.sh"]
