# Arc Remote Signer

Secure cryptographic signing service for Arc Chain validators, powered by AWS Nitro Enclaves — also known as **Nitro Enclave Signer**.

![Go Version](https://img.shields.io/badge/go-1.25-blue)

---

## Overview

Arc Remote Signer is a gRPC microservice designed specifically for Arc Chain validators, providing cryptographic key generation and signing operations with hardware-level security guarantees from AWS Nitro Enclaves. The service implements a dual-process architecture where a Proxy (outside the enclave) handles incoming requests while the Enclave (inside Nitro Enclave) performs all cryptographic operations.

Traditional key management systems store private keys in memory, making them vulnerable to compromise from privileged users, malware, or system vulnerabilities. Arc Remote Signer addresses these risks by isolating all cryptographic operations inside an AWS Nitro Enclave—a hardware-backed trusted execution environment with cryptographic attestation capabilities.

Deployed as a 1-to-1 sidecar alongside Arc Chain validator nodes, Arc Remote Signer provides verifiable proof that signing operations occur within a secure enclave, enabling zero-trust architectures where even the host system cannot access private key material.

## Features

- 🔐 **Hardware-isolated operations** - Validator key operations isolated in AWS Nitro Enclaves
- 🔑 **Ed25519 signatures** - Primary signing algorithm for Arc Chain validators with BLS support
- 📜 **Cryptographic attestation** - Verifiable proof of enclave execution for validator operations
- 🔄 **Envelope encryption** - Four-layer key protection (validator key → data key → KMS key → enclave key)
- 🚀 **High-performance gRPC** - Efficient binary protocol for low-latency validator signing
- 📊 **Full observability** - OpenTelemetry tracing and Datadog metrics
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

- [`docs/architecture.md`](./docs/architecture.md) — dual-process architecture, runtime flows, security model, deployment, API reference, troubleshooting
- [`docs/development.md`](./docs/development.md) — prerequisites, build/run commands, coding conventions, pre-commit hooks
- [`docs/testing.md`](./docs/testing.md) — test matrix and conventions

## Architecture

Arc Remote Signer uses a **dual-process architecture** with clear security boundaries between the Proxy (outside enclave) and Enclave (inside Nitro Enclave):

```
┌─────────────────────────────────────────────────────────────┐
│                  Arc Chain Validator                        │
└───────────────────────────┬─────────────────────────────────┘
                            │ gRPC (sidecar)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      Proxy (Host)                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   gRPC API   │  │   Signer     │  │  Providers   │       │
│  │   Handlers   │─▶│   Service    │─▶│ (KMS, Secrets│       │
│  └──────────────┘  └──────────────┘  │  Manager)    │       │
│                            │         └──────────────┘       │
│                            │ vsock/gRPC                     │
└────────────────────────────┼────────────────────────────────┘
                             │
                ┌────────────▼────────────┐
                │   Nitro Enclave         │
                │  ┌──────────────────┐   │
                │  │  Enclave gRPC    │   │
                │  │    Handlers      │   │
                │  └────────┬─────────┘   │
                │           │             │
                │  ┌────────▼─────────┐   │
                │  │  Key Decryption  │   │
                │  │  & Signing       │   │
                │  └────────┬─────────┘   │
                │           │             │
                │  ┌────────▼─────────┐   │
                │  │  NSM Attestation │   │
                │  └──────────────────┘   │
                └─────────────────────────┘
```

### Key Components

1. **Proxy** (`internal/app/`) - Runs outside the enclave, handles validator signing requests, manages AWS integrations (KMS for key decryption, Secrets Manager for configuration), caches attestation documents, and proxies signing operations to the enclave over vsock.

2. **Enclave** (`internal/enclave/`) - Runs inside an AWS Nitro Enclave, performs all cryptographic operations (key decryption, validator signing), maintains secure key material in memory, and generates attestation documents proving execution within the secure environment.

3. **Communication Layer** - Proxy and enclave communicate via gRPC over vsock (virtual socket), ensuring type-safe, versioned contracts between trust boundaries. Validator nodes communicate with the Proxy via standard gRPC.

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

### EnclaveService API (Internal)

**EnclaveService** is an **internal API** inside the Nitro Enclave, **not accessible to external clients**:

- **Port**: 10350 (internal vsock only, accessible only by Proxy)
- **Proto**: `proto/arc/enclave/v1/enclave.proto`
- **Methods**: `GenerateKey()`, `GetPublicKey()`, `SignMessage()`, `GetAttestation()`
- **Use case**: Internal communication between Proxy and Enclave over vsock

This full-featured API is used exclusively by the Proxy to communicate with the Enclave for cryptographic operations. Arc Chain validators do not interact with this API directly. The EnclaveService handles key generation, encrypted key material management, signing operations, and attestation document generation—all within the secure enclave environment.

## Deployment

Arc Remote Signer is deployed as a 1-to-1 sidecar with Arc Chain validator nodes on Nitro-enabled AWS EC2 instances.

## Reproducible Enclave Builds

The enclave Docker image is built reproducibly — identical source produces bit-for-bit identical images across builds. This ensures the PCR0 hash (derived from the enclave image) is stable and predictable, which is critical for attestation policy.

The enclave build uses a dedicated `docker/Dockerfile.enclave`, separate from the main `docker/Dockerfile` used by the signer targets. Key techniques:
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
│   │   └── provider/      # AWS integrations (KMS, Secrets Manager)
│   ├── enclave/           # Enclave (inside Nitro Enclave)
│   │   ├── public/        # Enclave gRPC handlers
│   │   ├── service/       # Enclave business logic
│   │   └── provider/      # Key storage, attestation
│   ├── common/            # Shared infrastructure
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
- [Nitro System Manager Documentation](https://docs.aws.amazon.com/enclaves/latest/user/set-up-nitro-enclave-dev-environment.html)
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
