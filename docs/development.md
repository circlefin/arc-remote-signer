# Development

Local development uses `deployments/docker-compose.yaml`. The default configuration uses LocalStack to simulate AWS services. All workflows use `make` targets, which handle dependency ordering.

For architecture, deployment topology, and the security model, see [architecture.md](architecture.md).
For test conventions and coverage expectations, see [testing.md](testing.md).

## Prerequisites

- Go 1.25+
- Docker and Docker Compose
- Make
- `pre-commit` (install via `brew install pre-commit`, then `pre-commit install`)

## Common Tasks

### Dependencies

| Command | Description |
|---------|-------------|
| `make up` | Build the local `signer-dev` image. Start LocalStack. |
| `make down` | Tear down the local environment: stop the app (via `app.pid`) and run `docker-compose down --remove-orphans` |
| `make dev` | `make up` + launch the app (typical dev entry point) |

The development settings use separate provider switches:

- `APP_PROVIDER_SECRETS_LOCALSTACK_ENABLED` selects LocalStack for Secrets Manager.
- `APP_PROVIDER_AWSKMS_LOCALSTACK_ENABLED` selects LocalStack for KMS.

The signer-dev image can use standard AWS KMS while `APP_ENV=dev`. Set
`APP_PROVIDER_AWSKMS_LOCALSTACK_ENABLED=false` and provide
`APP_PROVIDER_AWSKMS_ARNS` and AWS credentials. The development compose stack
still starts LocalStack, but the KMS proxy does not use it. Standard AWS KMS in
non-Nitro mode does not send enclave attestation.

### Build

| Command | Description |
|---------|-------------|
| `make proto` | Regenerate protocol buffer Go code |
| `make build` | Generate protos and build binary to `./bin/app` |

### Test

See [testing.md](testing.md) for the full test matrix and conventions. Top-level entry points:

| Command | Scope |
|---------|-------|
| `make test` | Unit + lint |
| `make test-it` | Unit + integration (starts localstack) |
| `make smoke` | Smoke tests against a running service |
| `make test-all` | All of the above |

## Conventions

- **Go version**: 1.25
- **Copyright header**: All `.go` files except generated `*_mock.go` files must carry the Circle Internet Group Apache 2.0 license header. The exception matches the `check-copyright-golang` pre-commit hook.
- **Commit messages**: `type(ticket|NOSTORY): description`, following [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for the `type` semantics. Valid tickets follow the project's Jira prefix.
- **Mocking**: `github.com/golang/mock` (v1.6.0). Mocks are `*_mock.go` files co-located with the interfaces they mock; regenerate with `mockgen`.
- **Config**: Viper-based, env var prefix `APP_`. See [architecture.md#common-production-settings](architecture.md#common-production-settings).
- **Logging**: Use the repo-local logger in `internal/common/logging/`.
- **Protocol Buffers**: Managed by `buf` (config version v2), definitions in `proto/`. Run `make proto` after editing.
- **gRPC**: Shared foundation in `internal/common/grpc/` with standardized client/server lifecycle and error normalization.

## Pre-commit Hooks

Enforced via `.pre-commit-config.yaml`:

- `go-fmt`, `golangci-lint`, `go-mod-tidy`, `go-unit-tests`
- `no-go-testing` — scans files named `test_*.go` for the literal `testing.T`; it does not parse imports, enforce Testify assertion style, or match the repository's standard `*_test.go` filenames
- `check-copyright-golang` — Circle copyright header on `.go` files except generated `*_mock.go`
- `terraform_fmt` — for `deploy/` configs

Run `pre-commit install` once after cloning to enable the hooks locally.

## Verification Before PR

1. `make build` — confirm the binary compiles (includes proto generation)
2. `make test` — unit tests + lint for code changes
3. `make test-it` — when changes touch provider integrations, gRPC behavior, enclave communication, or config
4. `make test-all` — for high-risk or release-critical changes

Signing-critical and signer-image changes also rely on the CI-only `smoke_eif`
job, which has no equivalent local `make` target. See
[CI-only EIF Image Validation](testing.md#ci-only-eif-image-validation).

## Project Structure

```
.
├── cmd/                    # CLI entry points (app, run-vsockproxy)
├── internal/
│   ├── app/                # Host application (app run)
│   │   ├── public/         # gRPC handlers
│   │   ├── service/        # Business logic (signer)
│   │   ├── provider/       # Secrets Manager + enclave client (no KMS on the host)
│   │   └── metrics/        # API metrics
│   ├── enclave/            # Enclave-side (inside Nitro Enclave)
│   │   ├── public/         # Enclave gRPC handlers
│   │   ├── service/        # Enclave business logic
│   │   ├── provider/       # awskms (KMS client), awsproxy, enclave (NSM), keystore
│   │   └── common/crypto/  # In-enclave AES, BLS, Ed25519 primitives
│   ├── vsockproxy/         # Host-side vsock↔AWS KMS bridge (app run-vsockproxy)
│   ├── common/             # Shared infrastructure
│   │   ├── byteproxy/      # vsock byte proxy + AWS route framing
│   │   ├── config/         # Viper config loader
│   │   ├── crypto/         # AES, random generation
│   │   ├── grpc/           # gRPC client/server/interceptors
│   │   ├── lifecycle/      # Runnable lifecycle management
│   │   ├── logging/        # Structured logging
│   │   ├── metric/         # Datadog metrics
│   │   └── telemetry/      # OpenTelemetry
│   └── smoke/              # End-to-end smoke tests
├── proto/                  # Protocol buffers
│   ├── arc/signer/v1/      # SignerService (external API)
│   └── arc/enclave/v1/     # EnclaveService (internal API)
├── docker/                 # Docker build configuration
├── deploy/                 # Terraform deployment configs
├── deployments/            # Docker Compose (localstack)
└── scripts/                # Build and utility scripts
```
