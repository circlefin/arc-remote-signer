# Arc Remote Signer

Secure cryptographic signing service for Arc Chain validators, powered by AWS Nitro Enclaves — also known as **Nitro Enclave Signer**.

![Go Version](https://img.shields.io/badge/go-1.25-blue)

---

## Overview

Arc Remote Signer is a gRPC microservice designed specifically for Arc Chain validators, providing cryptographic key generation and signing operations with hardware-level security guarantees from AWS Nitro Enclaves. The service runs as three runtime processes across two trust domains: a host application and standalone KMS traffic proxy outside the enclave, plus the signing application inside the Nitro Enclave.

Host-based signing services expose private keys to the host process's memory, where privileged access, malware, or system vulnerabilities can compromise them. Arc Remote Signer instead isolates private-key operations inside an AWS Nitro Enclave—a hardware-backed trusted execution environment with cryptographic attestation capabilities.

Deployed as a 1-to-1 sidecar alongside Arc Chain validator nodes, Arc Remote Signer uses enclave attestation to bind KMS access to an approved enclave image, so the host system cannot access plaintext private keys or data keys.

## Features

- 🔐 **Hardware-isolated operations** - Validator key operations isolated in AWS Nitro Enclaves
- 🔑 **Ed25519 signatures** - Primary signing algorithm for Arc Chain validators with BLS support
- 📜 **Cryptographic attestation** - Attestation-bound KMS access for approved enclave images
- 🔄 **Envelope encryption** - Private keys wrapped by KMS-protected data keys, with attestation-bound KMS responses decryptable only inside the enclave
- 🚀 **High-performance gRPC** - Efficient binary protocol for low-latency validator signing
- 📊 **Host observability** - OpenTelemetry tracing, Datadog metrics, and an optional Prometheus endpoint for the host application
- 🏗️ **Sidecar architecture** - 1-to-1 deployment alongside Arc Chain validator nodes
- ✅ **Comprehensive testing** - Unit, integration, and smoke test coverage

## Quick Start

Get the service running locally in 3 steps:

### Prerequisites

- Go 1.25+
- Docker and Docker Compose
- Make

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/circlefin/arc-remote-signer.git
cd arc-remote-signer

# 2. Install pre-commit hooks
brew install go pre-commit
pre-commit install

# 3. Start the development environment
make dev
```

The service will start on the default gRPC port with all dependencies running in Docker.

### Verify Installation

```bash
# Run smoke tests to verify everything works
make smoke
```

If all tests pass, the service is ready to use!

## Documentation

- [`docs/architecture.md`](./docs/architecture.md) — runtime processes and trust domains, runtime flows, security model, deployment, API reference, troubleshooting
- [`docs/development.md`](./docs/development.md) — prerequisites, build/run commands, coding conventions, pre-commit hooks
- [`docs/testing.md`](./docs/testing.md) — test matrix and conventions

## Architecture

Arc Remote Signer uses **three runtime processes across two trust domains**: the host application and standalone `app run-vsockproxy` process run on the EC2 host, while the enclave application runs inside the Nitro Enclave:

```
┌─────────────────────────────────────────────────────────────┐
│                  Arc Chain Validator                        │
└───────────────────────────┬─────────────────────────────────┘
                            │ gRPC (sidecar)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                        EC2 Host                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   gRPC API   │  │   Signer     │  │   Secrets    │       │
│  │   Handlers   │─▶│   Service    │─▶│   Manager    │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│       Host app (`app run`) │                                │
│                            │ gRPC: TCP (dev/CI), VSOCK (prod)│
└───────────────────────────┼─────────────────────────────────┘
                            │
                ┌───────────▼─────────────┐
                │   Nitro Enclave         │
                │  ┌──────────────────┐   │
                │  │  Enclave gRPC    │   │
                │  │    Handlers      │   │
                │  └────────┬─────────┘   │
                │           │             │
                │  ┌────────▼─────────┐   │
                │  │  KMS Client, Key │   │
                │  │ Decrypt & Signing│   │
                │  └────────┬─────────┘   │
                │           │             │
                │  ┌────────▼─────────┐   │
                │  │ NSM + awsproxy   │   │
                │  └──────────────────┘   │
                └─────────────────────────┘
                            │ KMS traffic
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ EC2 Host: standalone `app run-vsockproxy` process ───▶ KMS │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

1. **Host application** (`app run`, `internal/app/`) - Runs outside the enclave, handles validator requests, persists the wrapped key in AWS Secrets Manager, and passes temporary AWS credentials, KMS key ARNs, and the LocalStack selector during enclave initialization. It does not construct KMS requests, handle plaintext data keys, or fetch/cache attestation documents.

2. **KMS traffic proxy** (`app run-vsockproxy`, `internal/vsockproxy/`) - Runs as a separate host-side process. It routes opaque KMS traffic to LocalStack or to the regional AWS endpoint selected by the enclave. It restricts AWS routes to the regions in the configured KMS key ARNs.

3. **Enclave application** (`internal/enclave/`) - Runs inside an AWS Nitro Enclave, owns the AWS KMS client, attaches NSM-signed attestation to KMS requests, and routes them through the enclave-side `awsproxy`. It performs data-key and signing-key operations and keeps plaintext key material in enclave memory.

4. **Communication layer** - The host and enclave applications use gRPC over TCP on localhost in dev/CI and over VSOCK in Nitro production. Validator nodes communicate with the host application via standard gRPC.

For detailed layer architecture and shared infrastructure, see [`docs/architecture.md`](./docs/architecture.md).

## Usage

Arc Remote Signer exposes a gRPC API for Arc Chain validators to perform signing operations:

### SignerService API

**SignerService** is the **public API** exposed by the Proxy for Arc Chain validators:

- **Port**: 10340 (external, accessible from validator nodes)
- **Proto**: `proto/arc/signer/v1/signer.proto`
- **Methods**: `PublicKey()`, `Sign()`
- **Use case**: Arc Chain validators that need simple signing without managing key material directly

This simplified API abstracts away key management complexity, allowing validators to request public keys and signatures without handling encrypted key material.

### Example: Validator Integration

This example shows how Arc Chain validators interact with the service:

```go
package main

import (
    "context"
    "log"

    pb "github.com/circlefin/arc-remote-signer/proto/pb"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

func main() {
    // Connect to the service
    conn, err := grpc.NewClient("localhost:10340",
        grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    client := pb.NewSignerServiceClient(conn)
    ctx := context.Background()

    // Get the public key
    pubKeyResp, err := client.PublicKey(ctx, &pb.PublicKeyRequest{})
    if err != nil {
        log.Fatalf("PublicKey failed: %v", err)
    }
    log.Printf("Public key: %x", pubKeyResp.PublicKey)

    // Sign a message
    signResp, err := client.Sign(ctx, &pb.SignRequest{
        Message: []byte("message to sign"),
    })
    if err != nil {
        log.Fatalf("Sign failed: %v", err)
    }
    log.Printf("Signature: %x", signResp.Signature)
}
```

The example uses the default plaintext listener for local development. Production can enable server-authenticated TLS with the `APP_PUBLIC_SERVER_TLS_ENABLED`, `APP_PUBLIC_SERVER_TLS_CERT`, and `APP_PUBLIC_SERVER_TLS_KEY` settings documented in [`docs/architecture.md`](./docs/architecture.md#common-production-settings). It can optionally require client certificates by enabling `APP_PUBLIC_SERVER_TLS_CLIENTAUTH_ENABLED` and configuring `APP_PUBLIC_SERVER_TLS_CLIENTAUTH_CA` with a dedicated client CA bundle. The application authenticates membership in that CA; restricting access to Malachite depends on provisioning its client certificates exclusively to that workload.

### EnclaveService API (Internal)

**EnclaveService** is an **internal API** served inside the Nitro Enclave. It is not exposed as a validator-facing network API:

- **Port**: 10350 (TCP on localhost in dev/CI; VSOCK in Nitro production)
- **Proto**: `proto/arc/enclave/v1/enclave.proto`
- **Methods**: `Initialize()`, `GenerateKey()`, `GetPublicKey()`, `SignMessage()`
- **Use case**: Internal communication between the host and enclave applications

The host application calls this API over TCP in dev/CI or VSOCK in Nitro production; Arc Chain validators do not interact with it directly. Attestation remains enclave-local and is attached to KMS requests by the enclave-owned KMS client.

## Deployment

Arc Remote Signer is deployed as a 1-to-1 sidecar with Arc Chain validator nodes on Nitro-enabled AWS EC2 instances.

## Reproducible Enclave Builds

The enclave Docker image is built reproducibly — identical source produces bit-for-bit identical images across builds. This ensures the PCR0 hash (derived from the enclave image) is stable and predictable, which is critical for attestation policy.

The enclave build uses `docker/Dockerfile.enclave`. This build uses the
`prod` tag. The tag selects the Nitro runner and the VSOCK transport. The final
image contains only the enclave executable, `configs/enclave.yaml`, and the
startup script.

A `go list -deps` test examines the dependencies of `cmd/enclave`. The test fails if `cmd/enclave` imports the generic command package or a host-only dependency that is in the test list.

The signer targets use `docker/Dockerfile`. The production targets build the
host with the `prod` tag. This tag sets the host transport to
VSOCK and disables LocalStack. The production image contains only the
production host executable and production configuration. The production
launcher always starts the VSOCK proxy, the EIF, and the host application.

Local development and CI use the `signer-dev` target. This target uses the
development host build and the development enclave build. It supports TCP and
LocalStack. The production targets do not contain its executable, configuration,
or startup script.

Production uses one enclave target and one EIF. The build configuration has no
debug EIF target.
The EIF does not read `APP_ENV` or Datadog variables from the host. It does not
send logs, traces, or metrics to the host. The enclave launcher sends standard
output and standard error to `/dev/null`.

The `signer-dev` image is not an EIF. It can show local enclave process logs for
development. It does not have the security boundary of the production EIF.

The release pipeline does a test of the `signer-with-enclave` Docker archive on
a Nitro runner. The test starts the EIF with Nitro debug mode. Debug mode is a
runtime option. It does not create or change EIF bytes. The pipeline publishes
the same image digest to Cloudsmith and ECR. Staging and production must use
that digest.

Nitro debug mode does not validate a production KMS policy that uses PCR values.
A production-mode test is necessary for each PCR policy change.

Key reproducibility techniques:
- **Digest-pinned base images** (Go toolchain + Debian)
- **Snapshot-pinned apt** via `snapshot.debian.org` for deterministic packages
- **In-Docker Go build** with `-trimpath -buildvcs=false -ldflags=-buildid=`
- **Timestamp clamping** via `SOURCE_DATE_EPOCH` and targeted `find/touch`
- **Bind mounts** instead of `COPY` to avoid wall-clock layer timestamps

To verify locally:

```bash
make test-reproducibility
```

> **Note:** Updating any digest pin in `docker/Dockerfile.enclave` will change the enclave image and invalidate existing PCR hashes. See the warning in the Dockerfile header.

## Development

This project uses `make` targets as the standard workflow entry points. For full command details, conventions, and pre-commit hooks, see [`docs/development.md`](./docs/development.md).

### Project Structure

```
.
├── cmd/                    # CLI entry points
├── internal/
│   ├── app/               # Proxy (outside enclave)
│   │   ├── public/        # gRPC handlers
│   │   ├── service/       # Business logic
│   │   └── provider/      # Secrets Manager and enclave client
│   ├── enclave/           # Enclave (inside Nitro Enclave)
│   │   ├── public/        # Enclave gRPC handlers
│   │   ├── service/       # Enclave business logic
│   │   └── provider/      # KMS, key storage, attestation
│   ├── vsockproxy/        # Host-side vsock↔AWS KMS bridge (run-vsockproxy)
│   ├── common/            # Shared infrastructure
│   │   ├── byteproxy/     # vsock byte proxy + AWS route framing
│   │   ├── crypto/        # AES, random generation
│   │   ├── grpc/          # gRPC client/server/interceptors
│   │   ├── logging/       # Structured logging
│   │   ├── metric/        # Datadog metrics
│   │   └── telemetry/     # OpenTelemetry
│   └── smoke/             # End-to-end smoke tests
├── proto/                 # Protocol buffers
│   ├── arc/signer/v1/     # SignerService (external API)
│   └── arc/enclave/v1/    # EnclaveService (internal API)
├── docker/                # Docker build configuration
├── deployments/           # Docker Compose (localstack)
└── scripts/               # Build and utility scripts
```

## Security Model

Arc Remote Signer protects validator keys using Nitro Enclave isolation, envelope encryption, and attestation-backed key access controls.

## API Reference

Arc Remote Signer exposes:

- `SignerService` (public API): `proto/arc/signer/v1/signer.proto`
- `EnclaveService` (internal API): `proto/arc/enclave/v1/enclave.proto`

## Troubleshooting

See the troubleshooting section in [`docs/architecture.md`](./docs/architecture.md#troubleshooting).

## Contributing

We welcome bug reports and feature requests via [GitHub Issues](../../issues).
Circle maintains this project and will address issues at our discretion.

For security issues, please refer to our [Security Policy](./SECURITY.md) instead of opening a public issue.

## License

Copyright © 2026 Circle Internet Group

Licensed under the Apache License, Version 2.0. See http://www.apache.org/licenses/LICENSE-2.0 for details.

### Dependencies

This project includes dependencies under various open-source licenses:

- **gRPC** - Apache 2.0
- **Protocol Buffers** - BSD 3-Clause
- **AWS SDK for Go** - Apache 2.0
- **OpenTelemetry** - Apache 2.0
- **Testify** - MIT
- **GoMock** - Apache 2.0

For a complete list of dependencies:
```bash
go list -m all
```

## Acknowledgments

### Project Team

This project was developed by the Circle engineering team.

### Resources & References

**AWS Nitro Enclaves Documentation**:
- [AWS Nitro Enclaves](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
- [Nitro Enclaves development environment](https://docs.aws.amazon.com/enclaves/latest/user/set-up-nitro-enclave-dev-environment.html)
- [Attestation Document Format](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)

**Cryptography References**:
- [Ed25519 Signature Scheme](https://ed25519.cr.yp.to/)
- [BLS Signatures](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature)

**Go & gRPC Ecosystem**:
- [Go Project](https://golang.org/)
- [gRPC Documentation](https://grpc.io/docs/)
- [Protocol Buffers](https://developers.google.com/protocol-buffers)
- [Buf](https://buf.build/) - Protocol buffer management

**Security & Best Practices**:
- [Zero Trust Architecture](https://www.nist.gov/publications/zero-trust-architecture)
- [Confidential Computing Consortium](https://confidentialcomputing.io/)

### Support

For questions, issues, or discussions:
- **GitHub Issues**: Report bugs and request features
- **Documentation**: See [`docs/architecture.md`](./docs/architecture.md) for architecture and [`docs/development.md`](./docs/development.md) for development guidelines

---

**Ready to get started?** See the [Quick Start](#quick-start) section for installation instructions.
