# Development

Local development uses `deployments/docker-compose.yaml` with localstack to simulate AWS services. All workflows are driven through `make` targets, which handle dependency ordering automatically.

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
| `make up` | Build local enclave Docker image and start localstack |
| `make down` | Tear down the local environment: stop the app (via `app.pid`) and run `docker-compose down --remove-orphans` |
| `make dev` | `make up` + launch the app (typical dev entry point) |

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
- **Copyright header**: All `.go` files must carry the Circle Internet Group Apache 2.0 license header. Enforced by the `check-copyright-golang` pre-commit hook.
- **Commit messages**: `type(ticket|NOSTORY): description`, following [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for the `type` semantics. Valid tickets follow the project's Jira prefix.
- **Mocking**: `github.com/golang/mock` (v1.6.0). Mocks are `*_mock.go` files co-located with the interfaces they mock; regenerate with `mockgen`.
- **Config**: Viper-based, env var prefix `APP_`. See [architecture.md#configuration](architecture.md#configuration).
- **Logging**: Use the repo-local logger in `internal/common/logging/`.
- **Protocol Buffers**: Managed by `buf` (config version v2), definitions in `proto/`. Run `make proto` after editing.
- **gRPC**: Shared foundation in `internal/common/grpc/` with standardized client/server lifecycle and error normalization.

## Pre-commit Hooks

Enforced via `.pre-commit-config.yaml`:

- `go-fmt`, `golangci-lint`, `go-mod-tidy`, `go-unit-tests`
- `no-go-testing` — use `testify` assertions, not raw `testing`
- `check-copyright-golang` — Circle copyright header on every `.go` file
- `terraform_fmt` — for `deploy/` configs

Run `pre-commit install` once after cloning to enable the hooks locally.

## Verification Before PR

1. `make build` — confirm the binary compiles (includes proto generation)
2. `make test` — unit tests + lint for code changes
3. `make test-it` — when changes touch provider integrations, gRPC behavior, enclave communication, or config
4. `make test-all` — for high-risk or release-critical changes

## Project Structure

```
.
├── cmd/                    # CLI entry points
├── internal/
│   ├── app/                # Proxy (host-side)
│   │   ├── public/         # gRPC handlers
│   │   ├── service/        # Business logic
│   │   └── provider/       # AWS integrations (KMS, Secrets Manager)
│   ├── enclave/            # Enclave-side (inside Nitro Enclave)
│   │   ├── public/         # Enclave gRPC handlers
│   │   ├── service/        # Enclave business logic
│   │   └── provider/       # Key storage, attestation
│   ├── common/             # Shared infrastructure
│   │   ├── crypto/         # AES, random generation
│   │   ├── grpc/           # gRPC client/server/interceptors
│   │   ├── logging/        # Structured logging
│   │   ├── metric/         # Datadog metrics
│   │   └── telemetry/      # OpenTelemetry
│   └── smoke/              # End-to-end smoke tests
├── proto/                  # Protocol buffers
│   ├── arc/signer/v1/      # SignerService (external API)
│   └── arc/enclave/v1/     # EnclaveService (internal API)
├── docker/                 # Docker build configuration
├── deployments/            # Docker Compose (localstack)
└── scripts/                # Build and utility scripts
```
