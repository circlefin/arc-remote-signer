# Architecture

This document describes the dual-process architecture, runtime flows, security model, deployment topology, and API surface of Arc Remote Signer.

For day-to-day build/run commands, see [development.md](development.md).
For test conventions, see [testing.md](testing.md).

## Overview

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

## Runtime Flows

The following sections describe how the two processes interact at runtime, from initial startup through key generation and steady-state signing.

### Startup Sequence

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

### Key Generation Flow

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

### Signing Flow

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

## Deployment

Arc Remote Signer is deployed as a 1-to-1 sidecar alongside each Arc Chain validator node using Docker containers on AWS EC2 instances with Nitro Enclaves enabled.

### Docker Images

The project uses `docker buildx bake` (configured in `docker-bake.hcl`) to build three Docker image targets across two Dockerfiles. The `enclave` target lives in `docker/Dockerfile.enclave` (built reproducibly), and `signer` / `signer-with-enclave` live in `docker/Dockerfile`:

1. **enclave** (`docker/Dockerfile.enclave`) — Runs inside AWS Nitro Enclave
   - Contains the enclave application binary
   - Listens on port `10350` (internal vsock communication only)
   - Entry point: `run_enclave.sh`
2. **signer** (`docker/Dockerfile`) — Runs as proxy outside the enclave
   - Handles external gRPC requests
   - Communicates with enclave via vsock
   - Listens on port `10340` for gRPC API
   - Entry point: `run_proxy.sh`
3. **signer-with-enclave** (`docker/Dockerfile`) — Complete production setup
   - Includes both proxy and enclave applications
   - Contains the enclave image file (EIF)
   - Manages enclave lifecycle automatically
   - Entry point: `run.sh`

### Building Images

#### Local `signer` image (macOS or Linux)

A single `make` target builds the Go binary and the host-arch Docker image for the `signer` target — recommended for local development against a mock enclave (no `nitro-cli` or EIF needed):

```bash
# macOS (Apple Silicon → arm64 image)
make local-enclave-docker

# Linux or when you need a linux/amd64 image
APP_ENV=qa make local-enclave-docker
```

`APP_ENV=qa` is the toggle that switches `scripts/build.sh` into cross-compiling `linux/amd64` so Docker's `COPY bin/$TARGETARCH/app` resolves correctly.

#### Production image with bundled enclave (`signer-with-enclave`)

The `signer-with-enclave` target bundles a real Enclave Image File (EIF). Building the EIF only requires the `nitro-cli` binary — **a Nitro-Enclaves-enabled EC2 host is not needed to build an EIF**; that is only required to run an enclave.

1. Install `nitro-cli` by following the official AWS guide: https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html

2. Create a `docker-container` builder. The enclave bake target uses `rewrite-timestamp=true` for reproducible builds, which requires the `docker-container` driver (BuildKit >= 0.13.0):

   ```bash
   docker buildx create --name enclave-builder --driver docker-container --use
   ```

3. Run the end-to-end build:

   ```bash
   # 1. Build the linux/amd64 host binary
   APP_ENV=qa make build

   # 2. Build the enclave Docker image
   docker buildx bake --provenance=false --allow fs.read=./docker/certs enclave

   # 3. Package the Docker image into an EIF
   nitro-cli build-enclave \
     --docker-uri nitro-enclave-signer/enclave:latest \
     --output-file enclave.eif

   # 4. Bundle the EIF into the final signer-with-enclave image
   docker buildx bake \
     --set "signer-with-enclave.args.ENCLAVE_EIF=./enclave.eif" \
     signer-with-enclave
   ```

> [!NOTE]
> Different versions of `nitro-cli` bundle different kernel and init ramdisk images into the EIF, which changes the PCR0 and PCR2 measurements even when the application code is identical. Pin `nitro-cli` to a specific version and coordinate upgrades with downstream KMS key policy updates.

### AWS Prerequisites

Before deploying, provision the following AWS resources in the account that will run the signer. All snippets below use placeholder values (account ID `000000000000`, region `us-east-1`, etc.) — replace them with your own before applying.

#### EC2 host

- Nitro Enclaves enabled instance (for example: `m5.xlarge`, `c5.xlarge`)
- VPC configuration with security groups that allow inbound traffic from the validator node to the signer's gRPC port
- Enclave resources allocated via `/etc/nitro_enclaves/allocator.yaml` (memory, vCPUs sized for your workload)
- `nitro-cli` installed on the deployment host (needed to run the enclave image). If you are building the EIF on a separate machine, install `nitro-cli` there too — but the deployment host only needs it at runtime:
  - **Amazon Linux 2:** install and configure:
    ```bash
    sudo amazon-linux-extras enable aws-nitro-enclaves-cli
    sudo yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
    sudo usermod -aG ne $USER && sudo usermod -aG docker $USER
    sudo systemctl enable --now nitro-enclaves-allocator.service
    sudo systemctl enable --now docker
    ```
  - **Amazon Linux 2023:** install and configure:
    ```bash
    sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
    sudo usermod -aG ne $USER && sudo usermod -aG docker $USER
    sudo systemctl enable --now nitro-enclaves-allocator.service
    sudo systemctl enable --now docker
    ```
  - **Other distros (Ubuntu, Debian, …):** build from source from [aws/aws-nitro-enclaves-cli](https://github.com/aws/aws-nitro-enclaves-cli)
  - Full install guide: [Install the Nitro Enclaves CLI](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html)

#### AWS KMS key

The signer uses **envelope encryption**: a symmetric KMS key wraps a per-validator data key, which in turn encrypts the validator's private key stored in Secrets Manager.

- Create a **symmetric** key with key spec `SYMMETRIC_DEFAULT`. **Asymmetric / RSA keys are not supported.**
- A **multi-region** key is recommended — `APP_PROVIDER_AWSKMS_ARNS` accepts multiple ARNs and the signer fails over across them.
- The **key policy** must include an attestation-based condition so that only your enclave can call `Decrypt` / `GenerateDataKey` with the `Recipient` parameter. Use the PCR0 hash printed by `nitro-cli build-enclave` (the enclave image is built reproducibly — see [Reproducible Enclave Builds](../README.md#reproducible-enclave-builds) — so this hash is stable across rebuilds of the same source).
  - Enforce `kms:RecipientAttestation:ImageSha384` (PCR0 — the enclave image hash). The enclave image is built reproducibly, so this hash is stable across rebuilds of the same source with the same `nitro-cli` version.

> **Example only — replace `000000000000` with your account ID, `arn:aws:iam::000000000000:role/arc-signer-host` with the IAM role attached to the signer's EC2 instance, and the placeholder PCR values with the actual values from your enclave build.**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableRootAccountAdministration",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::000000000000:root" },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowEnclaveDecryptAndGenerateDataKey",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::000000000000:role/arc-signer-host" },
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:ImageSha384": "EXAMPLE_PCR0_REPLACE_WITH_VALUE_FROM_NITRO_CLI_BUILD_OUTPUT"
        }
      }
    }
  ]
}
```

Reference: [Using cryptographic attestation with AWS KMS](https://docs.aws.amazon.com/enclaves/latest/user/kms.html).

> **Note:** The attestation condition lives in the **KMS key policy** above — it is not required in the EC2 IAM role policy. The IAM role grants the host permission to call KMS; the key policy then enforces that only requests carrying a valid enclave attestation are honoured.

#### AWS Secrets Manager secret

Pre-create **one empty secret per validator**. The signer writes the wrapped validator key into it on the first run; on subsequent runs it reads the wrapped key back.

- **Secret type: Plaintext** (not key/value). The signer stores the wrapped key as a base64-encoded string in `SecretString`. Leave the initial value empty — the signer populates it on first run.

Recommended naming convention: `arc-chain/{env}/validator-{n}/key`.

> **Example only — replace the secret name and region with your own.**

```bash
aws secretsmanager create-secret \
  --name "arc-chain/dev/validator-1/key" \
  --description "Wrapped Arc validator signing key" \
  --region us-east-1
```

> **Note:** Create the secret using the CLI, not the AWS console. The signer treats any non-empty `SecretString` as an existing wrapped key and tries to base64-decode it on startup. The AWS console pre-fills the value with `{"":""}`, which is not empty and will cause startup to fail with `illegal base64 data`.

You will pass this name (or its full ARN) to the signer via `APP_SERVICE_SIGNER_KEYID`. On first run, if the secret has no stored value, the signer generates a new key and writes it automatically — no manual initialization needed.

#### IAM role on the EC2 host

Attach an instance profile / role to the signer's EC2 host with the four permissions below, scoped to the specific KMS key ARN and secret ARN you just created — not `*`.

> **Example only (single-region minimum) — replace `000000000000`, the KMS key ID, and the secret name with your own values.**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KMSEnvelopeOps",
      "Effect": "Allow",
      "Action": [
        "kms:GenerateDataKey",
        "kms:Decrypt"
      ],
      "Resource": "arn:aws:kms:us-east-1:000000000000:key/EXAMPLE-KEY-ID-1234-5678"
    },
    {
      "Sid": "SecretsManagerValidatorKey",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:000000000000:secret:arc-chain/dev/validator-1/key-*"
    }
  ]
}
```

The trailing `-*` on the secret ARN is required because Secrets Manager appends a random 6-character suffix to each secret's full ARN.

**Multi-region keys:** if you created a multi-region KMS key and replicated it to additional regions, add one `Resource` ARN per replica to the `KMSEnvelopeOps` statement. For example:

```json
"Resource": [
  "arn:aws:kms:us-east-1:000000000000:key/mrk-EXAMPLE-KEY-ID-1234-5678",
  "arn:aws:kms:us-west-2:000000000000:key/mrk-EXAMPLE-KEY-ID-1234-5678"
]
```

Each replica key also requires its own key policy with the attestation condition (the PCR0 value is the same across regions for the same EIF).

#### Wiring it up

Once the resources above exist, point the signer at them by setting:

- `APP_PROVIDER_AWSKMS_ARNS` — the KMS key ARN (or comma-separated list for multi-region)
- `APP_SERVICE_SIGNER_KEYID` — the Secrets Manager secret name or ARN

See [Configuration](#configuration) below for the full environment variable reference.

### Configuration

The service uses [Viper](https://github.com/spf13/viper) for configuration management with the following precedence (highest to lowest):

1. Environment variables
2. Configuration file
3. Default values

All environment variables use the `APP_` prefix. Nested keys use underscore style in env vars (for example, `provider.awskms.arns` -> `APP_PROVIDER_AWSKMS_ARNS`).

```bash
# Required - AWS configuration
# APP_PROVIDER_SECRETS_LOCALSTACK_REGION overrides the AWS region for Secrets Manager.
# On EC2, the SDK resolves region from instance metadata automatically — only set this if
# the SDK cannot detect the region (e.g. running outside EC2 or with --network bridge).
# In production, prefer the standard AWS_REGION env var instead.
export APP_PROVIDER_SECRETS_LOCALSTACK_REGION=us-east-1
export APP_PROVIDER_AWSKMS_ARNS=arn:aws:kms:us-east-1:000000000000:key/EXAMPLE-KEY-ID-1234-5678
# APP_SERVICE_SIGNER_KEYID accepts either the secret name or its full ARN.
export APP_SERVICE_SIGNER_KEYID=arc-chain/dev/validator-1/key

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

# Prometheus metrics (optional, disabled by default)
export APP_METRICS_PROMETHEUS_ENABLED=true
export APP_METRICS_PROMETHEUS_HOST=0.0.0.0
export APP_METRICS_PROMETHEUS_PORT=9090
export APP_METRICS_PROMETHEUS_PATH=/metrics
```

Example config file (`configs/app.yaml`):

```yaml
provider:
  awskms:
    arns: arn:aws:kms:us-east-1:000000000000:key/EXAMPLE-KEY-ID-1234-5678
  secrets:
    localstack:
      region: us-east-1

service:
  signer:
    keyId: arc-chain/dev/validator-1/key
```

Environment variables override config file values.

### Metrics

The signer exposes two complementary metric paths:

- **Datadog (statsd)** — API latency metrics, always initialized (see `metrics.statsd`).
- **Prometheus** — a scrape endpoint that surfaces gRPC server and runtime metrics. **Disabled by default**; enable via the `metrics.prometheus` block:

```yaml
metrics:
  prometheus:
    enabled: true
    host: 0.0.0.0
    port: 9090
    path: /metrics
```

Prometheus instrumentation is centralized in a [go-grpc-middleware](https://github.com/grpc-ecosystem/go-grpc-middleware) unary server interceptor on the public gRPC server — there are no hand-written per-handler counters. When enabled, the service serves the registry over HTTP at `host:port` + `path` (default `0.0.0.0:9090/metrics`).

Exposed series:

| Metric | Type | Notable labels |
| --- | --- | --- |
| `grpc_server_handled_total` | counter | `grpc_method`, `grpc_code`, `grpc_service`, `grpc_type` |
| `grpc_server_started_total` | counter | `grpc_method`, `grpc_service`, `grpc_type` |
| `grpc_server_handling_seconds` | histogram | `grpc_method`, `grpc_service`, `grpc_type` |
| `grpc_server_msg_received_total` / `grpc_server_msg_sent_total` | counter | `grpc_method`, `grpc_service`, `grpc_type` |
| `go_*` (e.g. `go_goroutines`) | gauge/counter | Go runtime collector |
| `process_*` (e.g. `process_resident_memory_bytes`) | gauge/counter | process collector |

All gRPC method/code combinations are pre-seeded to `0` at startup (`InitializeMetrics`), so counters appear before the first request. Example scrape config:

```yaml
scrape_configs:
  - job_name: arc-remote-signer
    metrics_path: /metrics
    static_configs:
      - targets: ['<signer-host>:9090']
```

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
