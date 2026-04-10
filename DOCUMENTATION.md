# Arc Remote Signer Detailed Documentation

## Architecture

### Overview

Arc Remote Signer uses a **dual-process architecture** with a hard security boundary between the Proxy (outside the enclave) and the Enclave (inside the Nitro Enclave). This separation ensures that private key material never exists in the host process — all cryptographic operations happen exclusively inside the hardware-isolated enclave.

The two processes communicate over **gRPC on vsock** (virtual socket), which is the only communication channel available in the Nitro Enclave environment. This means all inter-process contracts are typed and versioned via Protocol Buffers, and there is no shared memory or filesystem between the host and the enclave.

```
              Arc Chain Validator
                     │ gRPC :10340
                     ▼
┌────────────────────────────────────────┐
│              Proxy (Host)              │
│                                        │
│  ┌──────────┐  ┌──────────┐  ┌───────┐ │
│  │  Public  │  │ Service  │  │  KMS  │─┼──▶ AWS KMS
│  │(Handlers)│─▶│ (Signer) │─▶│  Sec  │ │
│  └──────────┘  └──────────┘  │  Mgr  │─┼──▶ AWS Secrets Manager
│                              └───┬───┘ │
└──────────────────────────────────┼─────┘
                                   │ gRPC over vsock :10350
                                   ▼
┌────────────────────────────────────────┐
│            Nitro Enclave               │
│                                        │
│  ┌──────────┐  ┌──────────┐  ┌───────┐ │
│  │  Public  │  │  Key /   │  │  Key  │ │
│  │(Handlers)│─▶│  Attn    │─▶│ Store │ │
│  └──────────┘  └──────────┘  │  NSM  │ │
│                              └───────┘ │
└────────────────────────────────────────┘
```

- **Proxy** (`internal/app/`) — handles incoming validator gRPC requests, orchestrates AWS integrations (KMS, Secrets Manager), caches attestation documents, and proxies signing operations to the enclave
- **Enclave** (`internal/enclave/`) — performs all cryptographic operations (key generation, decryption, signing), manages key material in memory, and generates attestation documents via the Nitro Security Module (NSM)

The enclave binary is packaged as an **Enclave Image File (EIF)**, which is cryptographically measured at build time. The PCR measurements in the attestation document reflect this image, allowing KMS key policies to enforce that decryption can only happen inside a known, unmodified enclave build.

### Runtime Flows

The following sections describe how the two processes interact at runtime, from initial startup through key generation and steady-state signing.

#### Startup Sequence

On startup, the Proxy fetches and caches the attestation document from the Enclave before handling any requests. This cached attestation is attached to all subsequent KMS API calls. The attestation document contains the enclave's public key and PCR measurements — KMS uses this to verify enclave identity and encrypts its response with the enclave's public key, so the plaintext data key is never exposed outside the enclave.

```
Proxy                                          Enclave
  │                                                │
  │── GetAttestation() ───────────────────────────▶│
  │◀─ { public_key,                                │
  │     pcr_measurements,                          │
  │     nsm_signature } ───────────────────────────│
  │                                                │
  │  (cache attestation_doc for KMS calls)         │
  │                                                │
  [ready to serve requests]
```

#### Key Generation Flow

Key generation is triggered on first startup when no key is found in Secrets Manager for the configured key ID:

1. Proxy calls KMS `GenerateDataKey` with the attestation cached during startup — KMS verifies the PCR measurements and encrypts the response with the enclave's public key
2. Proxy forwards the enclave-encrypted data key to the Enclave via `GenerateKey`
3. Enclave decrypts the data key internally, generates an ed25519 keypair, and encrypts the private key with the data key (AES-GCM)
4. Proxy stores the encrypted private key and KMS-encrypted data key in Secrets Manager

```
Proxy                             AWS KMS              Enclave               Secrets Manager
  │                                  │                    │                        │
  │── GetAttestation() ──────────────────────────────────▶│                        │
  │◀─ attestation_doc ────────────────────────────────────│                        │
  │                                  │                    │                        │
  │── GenerateDataKey(attestation)──▶│                    │                        │
  │◀─ { kms_encrypted_data_key,      │                    │                        │
  │     enclave_encrypted_data_key } │                    │                        │
  │                                  │                    │                        │
  │── GenerateKey(enclave_encrypted_data_key) ───────────▶│                        │
  │   (Enclave decrypts data key, generates ed25519,      │                        │
  │    encrypts private key with data key via AES-GCM,    │                        │
  │    caches plaintext key in enclave memory)            │                        │
  │◀─ { public_key, encrypted_private_key, nonce } ───────│                        │
  │                                  │                    │                        │
  │── PutSecret(encrypted_private_key,                    │                        │
  │              kms_encrypted_data_key, nonce) ──────────────────────────────────▶│
  │                                  │                    │                        │
```

The Proxy caches `encrypted_private_key`, `kms_encrypted_data_key`, and `nonce` in memory. The plaintext private key exists only inside the enclave's memory-isolated environment.

#### Signing Flow

Because the Proxy caches the encrypted key material after generation (or after loading from Secrets Manager), signing does not require a round-trip to Secrets Manager or KMS on the hot path:

1. Proxy retrieves cached `encrypted_private_key`, `enclave_encrypted_data_key`, and `nonce`
2. Proxy calls Enclave `SignMessage` with the message and encrypted key material
3. Enclave looks up the plaintext key from its in-memory cache (keyed by `hash(encrypted_private_key, dataKey, nonce)`); on cache miss, decrypts via the enclave-encrypted data key
4. Enclave performs the ed25519 signature and returns the result

```
Validator          Proxy                              Enclave
    │                │                                    │
    │── Sign(msg) ──▶│                                    │
    │                │── SignMessage(msg,                 │
    │                │     encrypted_private_key,         │
    │                │     enclave_encrypted_data_key,    │
    │                │     nonce) ───────────────────────▶│
    │                │   (Enclave looks up plaintext key  │
    │                │    from in-memory cache by hash;   │
    │                │    on cache miss, decrypts via     │
    │                │    enclave_encrypted_data_key)     │
    │                │ ◀─ signature ──────────────────────│
    │◀─ signature ───│                                    │
    │                │                                    │
```

The enclave's in-memory key cache is keyed by `hash(encrypted_private_key, dataKey, nonce)`. A cache miss triggers full decryption using the enclave-encrypted data key — the KMS-encrypted data key stored in Secrets Manager is never used on the signing path.

## Security Model

Arc Remote Signer protects validator private keys through hardware isolation, envelope encryption, and attestation-backed controls.

### Security Guarantees

| Threat | Protection |
|--------|------------|
| Privileged access | Keys isolated in hardware-backed enclave; root/hypervisor cannot access |
| Memory inspection | CPU-enforced memory isolation; no shared memory with host |
| Malware and code tampering | Validated code identity verified via attestation |
| Key exfiltration | Keys never leave enclave in plaintext; only signatures returned |
| Key at rest | Private key stored in Secrets Manager encrypted with AES-GCM data key; data key itself encrypted by AWS KMS — neither is usable without enclave decryption |

### Envelope Encryption

Arc Remote Signer uses envelope encryption to protect validator private keys at rest. Rather than encrypting the key directly with KMS (which has throughput limits), a short-lived data key performs the actual encryption while KMS protects only the data key. The enclave's public key adds a final layer ensuring only the enclave itself can unwrap the key material:

1. Validator private key encrypted with a data key
2. Data key protected by AWS KMS key material
3. KMS responses encrypted with enclave public key from attestation
4. Only enclave private key can decrypt returned key material

```
Validator Private Key
  └── encrypted by Data Key (AES-GCM)
        └── Data Key encrypted by AWS KMS Key
              └── KMS response encrypted by Enclave Public Key (from attestation)
                    └── only Enclave Private Key can unwrap  ← lives exclusively in enclave memory
```

### Attestation and KMS Integration

Attestation is the mechanism that binds KMS access to a specific, verified enclave build. KMS key policies enforce PCR conditions, so decryption only succeeds if the request originates from an unmodified enclave with matching measurements — even a privileged host process cannot satisfy these conditions.

1. Enclave generates attestation document (public key + PCR measurements + signed metadata)
2. Proxy sends attestation with KMS requests
3. KMS validates attestation and encrypts response to enclave key
4. Enclave decrypts and uses key material internally

See the AWS documentation for further reference:
- [Using cryptographic attestation with AWS KMS](https://docs.aws.amazon.com/enclaves/latest/user/kms.html) — attestation flow and KMS key policy configuration
- [Cryptographic attestation support in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/cryptographic-attestation.html) — KMS-side attestation mechanism details

```
Enclave                  Proxy                        AWS KMS
   │                        │                              │
   │  (on startup)          │                              │
   │◀─ GetAttestation() ────│                              │
   │── attestation_doc ────▶│                              │
   │   (public_key +        │                              │
   │    PCR measurements)   │                              │
   │                        │                              │
   │                        │── KMS request +              │
   │                        │   attestation_doc ──────────▶│
   │                        │              (KMS checks PCR │
   │                        │               against policy)│
   │                        │◀─ response encrypted         │
   │                        │   with enclave public_key ───│
   │                        │                              │
   │◀─ encrypted response ──│                              │
   │  (only enclave private │                              │
   │   key can decrypt)     │                              │
```

## Development

Local development uses `deployments/docker-compose.yaml` with localstack to simulate AWS services. All workflows are driven through `make` targets, which handle dependency ordering automatically.

**Dependencies**

| Command | Description |
|---------|-------------|
| `make up` | Build local enclave Docker image and start localstack |
| `make down` | Stop localstack |
| `make dev` | `make up` + launch the app (typical dev entry point) |

**Build**

| Command | Description |
|---------|-------------|
| `make proto` | Regenerate protocol buffer Go code |
| `make build` | Generate protos and build binary to `./bin/app` |

**Test**

| Command | Scope | Requires |
|---------|-------|----------|
| `make test` | Unit + lint | — |
| `make test-it` | Unit + integration | localstack |
| `make smoke` | Smoke (end-to-end) | running service |
| `make test-all` | All of the above | localstack + running service |

Test files are co-located with source and use build tags to control scope: integration tests use `//go:build integration` (`*_integration_test.go`), smoke tests use `//go:build smoke` (`internal/smoke/`).

## Deployment

Arc Remote Signer is deployed as a 1-to-1 sidecar alongside each Arc Chain validator node using Docker containers on AWS EC2 instances with Nitro Enclaves enabled.

### Docker Images

The project uses `docker buildx bake` (configured in `docker-bake.hcl`) to build three Docker image targets defined in `docker/Dockerfile`:

1. **enclave** - Runs inside AWS Nitro Enclave
   - Contains the enclave application binary
   - Listens on port `10350` (internal vsock communication only)
   - Entry point: `run_enclave.sh`
2. **signer** - Runs as proxy outside the enclave
   - Handles external gRPC requests
   - Communicates with enclave via vsock
   - Listens on port `10340` for gRPC API
   - Entry point: `run_proxy.sh`
3. **signer-with-enclave** - Complete production setup
   - Includes both proxy and enclave applications
   - Contains the enclave image file (EIF)
   - Manages enclave lifecycle automatically
   - Entry point: `run.sh`

### Building Images

```bash
# Build all images
docker buildx bake

# Build specific target
docker buildx bake signer

# Build with enclave (requires EIF file)
docker buildx bake --set "signer-with-enclave.args.ENCLAVE_EIF=path/to/enclave.eif" signer-with-enclave

# Build just the enclave image
docker buildx bake enclave
```

### AWS Prerequisites

To deploy this service in production, you need:

- EC2 instance with Nitro Enclaves enabled (for example: `m5.xlarge`, `c5.xlarge`)
- IAM role with permissions for:
  - AWS KMS: `kms:Decrypt`, `kms:GenerateDataKey`
  - AWS Secrets Manager: `secretsmanager:GetSecretValue`, `secretsmanager:PutSecretValue`
- VPC configuration with appropriate security groups
- Enclave resources allocated (memory, vCPUs)

### Configuration

The service uses [Viper](https://github.com/spf13/viper) for configuration management with the following precedence (highest to lowest):

1. Environment variables
2. Configuration file
3. Default values

All environment variables use the `APP_` prefix. Nested keys use underscore style in env vars (for example, `provider.awskms.arns` -> `APP_PROVIDER_AWSKMS_ARNS`).

```bash
# Required - AWS configuration
export APP_PROVIDER_SECRETS_LOCALSTACK_REGION=us-east-1
export APP_PROVIDER_AWSKMS_ARNS=arn:aws:kms:us-east-1:123456789:key/abc-123
export APP_SERVICE_SIGNER_KEYID=your-secret-id

# Enclave configuration
export APP_PROVIDER_ENCLAVE_NITROENCLAVE_ENABLED=true
export APP_PROVIDER_ENCLAVE_NITROENCLAVE_CID=16
export APP_PROVIDER_ENCLAVE_NITROENCLAVE_PORT=10350

# Service configuration
export APP_PUBLIC_SERVER_PORT=10340
export APP_PROFILER_ENABLED=false

# Observability (optional)
export APP_OTLP_ENDPOINT=localhost:4317
export DD_AGENT_HOST=localhost
export DD_SERVICE=arc-signer
export DD_ENV=prod
```

Example config file (`configs/app.yaml`):

```yaml
provider:
  awskms:
    arns: arn:aws:kms:us-east-1:123456789:key/abc-123
  secrets:
    localstack:
      region: us-east-1

service:
  signer:
    keyId: prod/arc/validator/key1
```

Environment variables override config file values.

### Production Deployment Notes

- Deployment model: 1-to-1 sidecar architecture
- External API port: `10340`
- Enclave operations remain inside Nitro Enclave boundary

Deployment scripts in `docker/`:

- `run.sh`
- `run_proxy.sh`
- `run_enclave.sh`

## API Reference

### Protocol Buffers

- SignerService (public): `proto/arc/signer/v1/signer.proto`
- EnclaveService (internal): `proto/arc/enclave/v1/enclave.proto`

### Supported Algorithms

- Ed25519 (default)
- BLS12-381 (optional)

### Key Operations

**SignerService** (public, port 10340):

| Method | Request | Response |
|--------|---------|----------|
| `PublicKey` | _(empty)_ | `public_key bytes` |
| `Sign` | `message bytes` | `signature bytes` |

**EnclaveService** (internal, port 10350 vsock):

| Method | Request | Response |
|--------|---------|----------|
| `GenerateKey` | `algorithm`, `enclave_encrypted_data_key` | `public_key`, `encrypted_private_key`, `nonce` |
| `GetPublicKey` | `algorithm`, `encrypted_key_material` | `public_key` |
| `SignMessage` | `algorithm`, `encrypted_key_material`, `message` | `signature` |
| `GetAttestation` | _(empty)_ | `attestation_document` |

`encrypted_key_material` is a composite field containing `encrypted_private_key`, `enclave_encrypted_data_key`, and `nonce`. For full field definitions see the proto files listed above.

### Error Handling

| Code | Meaning | Common Causes |
|------|---------|---------------|
| `OK (0)` | Success | — |
| `INVALID_ARGUMENT (3)` | Bad request | Missing or malformed message payload, unknown algorithm |
| `NOT_FOUND (5)` | Resource missing | Key not found in Secrets Manager for the configured key ID |
| `INTERNAL (13)` | Server error | KMS/Secrets Manager call failed, enclave decryption error, signing failure |
| `UNAVAILABLE (14)` | Service unreachable | Enclave not running, vsock connection failure |

## Troubleshooting

### Common Issues

Service fails with enclave connection error:

- Verify enclave is running: `nitro-cli describe-enclaves`
- Verify configured CID (default `16`)
- Inspect enclave logs: `nitro-cli console --enclave-id <id>`

Failed to retrieve attestation document:

- Verify `/dev/nsm` exists in enclave runtime
- Verify attestation path in enclave startup logs

Persistent signing latency:

- First operation warm-up is expected
- For sustained latency, inspect profiling output (`pprof` path)

AWS permission errors:

- Verify IAM role permissions for KMS/Secrets Manager
- Verify region and target resource IDs

Proto mismatch issues:

- Regenerate protos: `make proto`
- Rebuild host/enclave binaries

### Debugging

Enable debug logging:

```bash
APP_LOG_LEVEL=debug ./bin/app
```

For enclave-focused debugging:

- `nitro-cli console --enclave-id <id>`
- `nitro-cli describe-enclaves`
