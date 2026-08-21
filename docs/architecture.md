# Architecture

This document describes the three runtime processes across two trust domains, runtime flows, security model, deployment topology, and API surface of Arc Remote Signer.

For day-to-day build/run commands, see [development.md](development.md).
For test conventions, see [testing.md](testing.md).

## Overview

Arc Remote Signer uses **three runtime processes across two trust domains**. The host application (`app run`) and standalone KMS traffic proxy (`app run-vsockproxy`) run on the EC2 host; the enclave application runs inside the Nitro Enclave. The trust boundary ensures that private key material never exists in either host process — all cryptographic operations happen exclusively inside the hardware-isolated enclave.

The host and enclave applications communicate over gRPC: TCP on localhost in dev/CI and VSOCK in Nitro production. In Nitro, VSOCK is the enclave's communication channel to the host. All inter-process contracts are typed and versioned via Protocol Buffers, and there is no shared memory or filesystem across the trust boundary.

```
              Arc Chain Validator
                     │ gRPC :10340
                     ▼
┌────────────────────────────────────────┐
│              EC2 Host                  │
│  ┌──────────┐  ┌──────────┐  ┌───────┐ │
│  │  Public  │─▶│ Service  │─▶│  Sec  │─┼──▶ AWS Secrets Manager
│  │(Handlers)│  │ (Signer) │  │  Mgr  │ │
│  └──────────┘  └──────────┘  └───────┘ │
│  Host application (`app run`)           │
│                                         │
│  `app run-vsockproxy` (separate process)├──▶ AWS KMS
└────────────────────┬───────────────────┘
                     │ gRPC :10350
                     │ TCP (dev/CI), VSOCK (Nitro)
                     ▼
┌────────────────────────────────────────┐
│              Nitro Enclave             │
│  ┌──────────┐  ┌──────────┐  ┌───────┐ │
│  │  Public  │─▶│  Key /   │─▶│  Key  │ │
│  │(Handlers)│  │  Attn    │  │ Store │ │
│  └──────────┘  └──────────┘  └───────┘ │
│  ┌──────────────────────────────┐      │
│  │ KMS client + NSM + awsproxy  │      │
│  └──────────────────────────────┘      │
└────────────────────────────────────────┘
```

The enclave owns the KMS client. In Nitro mode, it attaches its NSM attestation
as KMS `RecipientInfo`. Requests travel through the enclave-side `awsproxy` and
the host-side `vsockproxy`. For standard AWS KMS, the host proxy dials the
regional endpoint from the route header. It limits routes to regions from the
configured ARNs. For LocalStack, the host proxy dials the fixed LocalStack
service endpoint. Nitro mode does not support LocalStack.

- **Host application** (`app run`, `internal/app/`) — handles incoming validator gRPC requests, persists the wrapped key in Secrets Manager, and passes temporary AWS credentials, KMS key ARNs, and the LocalStack selector during enclave initialization. It does not construct KMS requests or handle plaintext data keys.
- **KMS traffic proxy** (`app run-vsockproxy`, `internal/vsockproxy/`) — runs as a separate host process. It forwards opaque KMS traffic to LocalStack or to AWS regions from the configured KMS key ARNs.
- **Enclave application** (`internal/enclave/`) — owns the AWS KMS client and performs all cryptographic operations (data-key mint/decrypt, key generation, decryption, signing), manages key material in memory, and requests attestation documents from the Nitro Security Module (NSM).

The enclave binary is packaged as an **Enclave Image File (EIF)**, which is cryptographically measured at build time. The PCR measurements in the attestation document reflect this image, allowing KMS key policies to enforce that decryption can only happen inside a known, unmodified enclave build.

## Runtime Flows

The following sections describe how the runtime processes interact, from initial startup through key generation and steady-state signing.

### Startup Sequence

On startup, the host application retrieves temporary AWS credentials. The host
application also reads the KMS settings. It calls Enclave `Initialize` with the
credentials, key ARNs, and LocalStack selector. The Enclave builds a KMS client.
The Enclave keeps the KMS client in memory. It then runs a `GenerateDataKey`
probe through the KMS traffic proxy chain. The probe validates KMS access and
the supplied credentials. The host application does not fetch or cache the KMS
recipient attestation. In Nitro mode, the enclave-owned KMS client attaches
attestation as `RecipientInfo` (see [Attestation and KMS
Integration](#attestation-and-kms-integration)).

```
Host application                                Enclave                 AWS KMS
       │                                            │                       │
       │── Initialize(credentials, ARNs, selector) ▶│                       │
       │                                            │── GenerateDataKey ───▶│  (reachability +
       │                                            │◀─ ok ─────────────────│   credential probe)
       │◀─ InitializeResponse ──────────────────────│                       │
       │  (enclave retains the KMS client)          │                       │
       │                                            │                       │
  [ready to serve requests]
```

### Key Generation Flow

Key generation is triggered when the configured, pre-created Secrets Manager secret has no stored key value:

1. The host application calls the Enclave `GenerateKey(algorithm)`; no data key is supplied by the host
2. Enclave calls KMS `GenerateDataKey` with its attestation as `RecipientInfo`. In Nitro, KMS returns `CiphertextForRecipient`, which the enclave process decrypts with its in-memory RSA private key; in dev/CI, KMS returns the plaintext data key. The Enclave then generates the signing keypair, encrypts the private key with AES-GCM, and caches the plaintext signing key
3. Enclave returns a self-contained `SecretEnvelope { algorithm, kms_encrypted_data_key, encrypted_private_key, nonce }` plus the public key
4. The host calls Enclave `GetPublicKey` with the new envelope.
5. In Nitro mode, the enclave creates an attestation document for the public key.
6. The host confirms that both enclave responses contain the same public key.
7. The host maps the envelope to a stored `Header` and writes it to Secrets Manager.

```
Host application      Enclave                 AWS KMS             Secrets Manager
       │                  │                       │                         │
       │── GenerateKey ──▶│                       │                         │
       │                  │── GenerateDataKey ───▶│                         │
       │                  │◀─ ciphertext blobs ───│                         │
       │                  │                       │                         │  (RSA-decrypt data key;
       │                  │                       │                         │   generate signing key;
       │                  │                       │                         │   AES-GCM encrypt private key; cache)
       │◀─ public key + ──│                       │                         │
       │   SecretEnvelope │                       │                         │
       │── GetPublicKey ─▶│                       │                         │
       │                  │  (NSM attests key)    │                         │
       │◀─ key + document │                       │                         │
       │── PutSecret(Header from SecretEnvelope) ──────────────────────────▶│
       │                  │                       │                         │
```

The host application keeps the `SecretEnvelope` in memory. It also keeps the
public key and its attestation document in memory. Only enclave memory contains
the plaintext private key and the plaintext data key.

### Signing Flow

Because the host application holds the `SecretEnvelope` after generation or loading it from Secrets Manager, signing does not require a Secrets Manager round-trip on the hot path:

1. The host application relays the held `SecretEnvelope` and the message to Enclave `SignMessage`
2. Enclave looks up the plaintext key from its in-memory cache (keyed by a hash of the envelope's algorithm + ciphertext fields); on a cache miss it KMS-decrypts the data key in-enclave, AES-GCM-decrypts the private key, and caches it
3. Enclave performs the signature (Ed25519 or BLS) and returns the result

```
Validator          Host application       Enclave                 AWS KMS
    │                      │                  │                         │
    │── Sign(msg) ────────▶│                  │                         │
    │                      │── SignMessage ──▶│                         │
    │                      │                  │ (cache hit: sign)       │
    │                      │                  │ (cache miss: Decrypt) ─▶│
    │                      │                  │◀─ encrypted response ───│
    │                      │                  │ (RSA-decrypt; AES-decrypt;
    │                      │                  │  cache; sign)           │
    │                      │◀─ signature ─────│                         │
    │◀─ signature ─────────│                  │                         │
```

The enclave's in-memory key cache is keyed by `envelopeCacheKey` — a hash over the envelope's algorithm and its ciphertext fields (`kms_encrypted_data_key`, `encrypted_private_key`, `nonce`). A warm hit needs no KMS work; a miss triggers an in-enclave KMS `Decrypt` of the data key followed by AES-GCM decryption of the private key.

### Public Key Attestation Flow

During signer initialization, the host calls Enclave `GetPublicKey`. The enclave
gets the public key from its loaded signing key. In Nitro mode, the enclave asks
NSM to create a signed attestation document. The signed `user_data` field
contains the exact public key bytes. The host keeps the public key and document
in memory. It also reads the earliest certificate expiry from the document.

Each public `SignerService.PublicKey` request returns the pair from host memory.
The request does not call the enclave or NSM. The request does not contain a
nonce. The cache does not use a fixed TTL. A background task gets a new document
before the first certificate expires. It only accepts the same public key and a
later certificate expiry. A refresh error keeps the last valid document and
starts a bounded retry. `PublicKey` returns `Unavailable` after the document
expires.

The signed timestamp records when NSM created the document. It does not prove
that the enclave is currently live.

An external verifier runs outside the host and proxy trust boundary. It rejects
a missing or empty document. It validates the NSM signature and certificate
chain against a pinned AWS Nitro root CA. It checks each certificate validity
period at verification time. The verifier also validates the PCR values. The
verifier checks that `user_data` matches `public_key`. In dev/CI, the enclave
returns an empty attestation document.

```
Signer startup     Host application       Enclave                  NSM
    │                      │                  │                       │
    │                      │── GetPublicKey ─▶│                       │
    │                      │                  │── Attest(public key) ▶│
    │                      │                  │◀─ signed document ────│
    │                      │◀─ key + document │                       │
    │                      │  cache pair      │                       │
    │                      │                  │                       │
Validator                  │                  │                       │
    │── PublicKey() ──────▶│                  │                       │
    │◀─ cached pair ───────│                  │                       │
    │                      │                  │                       │
    │                      │── GetPublicKey ─▶│                       │
    │                      │                  │── Attest(public key) ▶│
    │                      │                  │◀─ signed document ────│
    │                      │◀─ key + document │                       │
    │                      │  refresh cache   │                       │
```

### Multi-Region KMS Routing and Failover

`APP_PROVIDER_AWSKMS_ARNS` accepts one or more KMS key ARNs (typically the regional replicas of a multi-region key). The enclave builds one KMS client per ARN, each pinned to that ARN's region, and fails over across them in order: if a KMS call fails, the failing client is moved to the back and the next ARN's region is tried, so a single-region KMS disruption degrades to the next configured region rather than failing the request.

Because the enclave has no direct network access, each KMS call uses the proxy chain:

1. The enclave's KMS client prepends a small route header (AWS service + region) when it connects to the enclave-side `awsproxy`, which relays it alongside the request bytes over TCP in dev/CI or VSOCK in Nitro production
2. The host-side `vsockproxy` reads that header. It dials LocalStack when `APP_PROVIDER_AWSKMS_LOCALSTACK_ENABLED=true`.
3. Otherwise, `vsockproxy` dials `kms.<region>.amazonaws.com:443`. The configured ARN regions form an **allowlist**. The proxy rejects a route for another region.

The allowlist is a security control, not just routing: the host relays bytes it cannot decrypt on behalf of the enclave, and bounding the dial target to the operator-configured ARN regions prevents the relayed stream from being used to reach an arbitrary host (SSRF). The host `vsockproxy` therefore consumes the same `APP_PROVIDER_AWSKMS_ARNS` value as the enclave to build this allowlist.

## Security Model

Arc Remote Signer protects validator private keys through hardware isolation, envelope encryption, and attestation-backed controls.

### Security Guarantees

| Threat | Protection |
|--------|------------|
| Privileged access | Keys isolated in hardware-backed enclave; root/hypervisor cannot access |
| Memory inspection | CPU-enforced memory isolation; no shared memory with host |
| Malware and code tampering | Validated code identity verified via attestation |
| Key exfiltration | Private keys never leave the enclave in plaintext; the validator-facing API returns only public keys and signatures |
| Key at rest | Private key stored in Secrets Manager encrypted with AES-GCM data key; data key itself encrypted by AWS KMS — neither is usable without enclave decryption |

### Envelope Encryption

Arc Remote Signer uses envelope encryption to protect validator private keys at rest. A per-validator data key encrypts the private key with AES-GCM, and AWS KMS protects that data key:

1. Validator private key encrypted with a data key
2. KMS-encrypted data key stored as a `CiphertextBlob`

```
Validator Private Key
  └── encrypted by Data Key (AES-GCM)
        └── Data Key encrypted by AWS KMS Key (`CiphertextBlob`)
```

Attestation protects the separate KMS response path. The enclave process generates an in-memory RSA key pair, and NSM signs an attestation document containing the RSA public key. With that attestation in `RecipientInfo`, KMS returns the data key as `CiphertextForRecipient`, encrypted to the attested public key. The proxy chain can relay that response but cannot decrypt it; the enclave process decrypts it with the corresponding in-memory RSA private key.

### Attestation and KMS Integration

Attestation binds recovery of KMS-protected data keys to a verified enclave build. KMS key policies enforce PCR conditions and KMS encrypts successful responses to the attested enclave key, so host credentials alone cannot recover plaintext data keys.

1. The enclave process generates an in-memory RSA key pair and asks NSM to sign an attestation document containing the RSA public key, PCR measurements, and metadata
2. The **enclave** owns the KMS client and attaches its attestation as `RecipientInfo` on KMS `GenerateDataKey` and `Decrypt` calls; `awsproxy` inside the enclave and `vsockproxy` on the host relay the network traffic without constructing the requests
3. KMS validates the attestation against the key policy and encrypts the response to the enclave's key (`CiphertextForRecipient`)
4. The enclave process decrypts the response with the corresponding in-memory RSA private key — the plaintext never leaves the enclave, even though the proxy chain carries the bytes

See the AWS documentation for further reference:
- [Using cryptographic attestation with AWS KMS](https://docs.aws.amazon.com/enclaves/latest/user/kms.html) — attestation flow and KMS key policy configuration
- [Cryptographic attestation support in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/cryptographic-attestation.html) — KMS-side attestation mechanism details

```
Enclave                    awsproxy / host vsockproxy           AWS KMS
   │                                  │                              │
   │  (NSM attestation held           │                              │
   │   in-enclave)                    │                              │
   │── KMS request + attestation ────▶│── relay ────────────────────▶│
   │                                  │              (KMS checks PCR │
   │                                  │               against policy)│
   │◀─ response encrypted ────────────│◀─ CiphertextForRecipient ────│
   │   to enclave key (relayed;       │                              │
   │   host cannot read it)           │                              │
   │  (RSA-decrypted in-enclave)      │                              │
```

## Deployment

Arc Remote Signer is deployed as a 1-to-1 sidecar alongside each Arc Chain validator node using Docker containers on AWS EC2 instances with Nitro Enclaves enabled.

### Docker Images

The `docker-bake.hcl` file specifies the Docker image targets. The project uses `docker buildx bake` to build these targets. The project has three production targets and one development target. The `enclave` target uses `docker/Dockerfile.enclave`. The build from this Dockerfile is reproducible. The signer targets use `docker/Dockerfile`:

1. **enclave** (`docker/Dockerfile.enclave`) runs inside an AWS Nitro Enclave.
   - The build uses the `prod` tag.
   - The enclave listens on port `10350` over VSOCK.
   - The entry point is `run_enclave.sh`.
2. **signer** (`docker/Dockerfile`) runs the production host application outside the enclave.
   - The build uses the `prod` tag.
   - The host handles external gRPC requests.
   - The host communicates with the enclave over VSOCK.
   - The image does not contain development configuration or executables.
   - The host listens on port `10340` for the gRPC API.
   - The entry point is `run_proxy.sh`.
3. **signer-with-enclave** (`docker/Dockerfile`) is the complete production image.
   - The image includes the proxy and enclave applications.
   - The image contains the enclave image file (EIF).
   - The launcher always starts the VSOCK proxy, the EIF, and the host application.
   - The entry point is `run.sh`.
4. **signer-dev** (`docker/Dockerfile`) is the local and CI development image.
   - The image uses the common runtime base image.
   - The image does not inherit from `signer`.
   - The image uses the development host and enclave builds.
   - The image contains the standalone enclave executable and the development startup script.
   - The launcher starts the enclave process directly over TCP.
   - The image does not use a Nitro EIF.
   - The image is not part of the production image matrix.

#### Secure EIF boundary

Production uses one `enclave` target and one EIF. The build configuration has no
debug EIF target. Staging and production use the same `signer-with-enclave`
image digest.

The host does not send `APP_ENV`, Datadog variables, logs, traces, or metrics to
the EIF. The enclave launcher sends standard output and standard error to
`/dev/null`. Host configuration and host observability continue to operate
outside the enclave.

The `signer-dev` target runs the enclave executable as a host process outside a
Nitro enclave. It can show local process logs. It does not have the security
boundary of the production EIF.

CI uses a test-only shell wrapper. The wrapper adds the Nitro CLI `--debug-mode`
option when it starts the production EIF. The production launcher does not
accept this option. Debug mode does not change the EIF bytes. This test does not
validate a production KMS policy that uses PCR values.

### Building Images

#### Local `signer-dev` image (macOS or Linux)

Use this command to build the `signer-dev` target. Use this image to run the host and enclave processes in a local environment. This build does not require `nitro-cli` or an EIF:

```bash
make local-enclave-docker
```

The `app-builder` stage builds the development host, the production host, and
the development enclave executable. The production host uses the
`prod` tag. You do not need a precompiled binary. The
`docker buildx bake` command does all build steps. The production `signer` and
`signer-with-enclave` targets do not contain development assets.

#### Production image with bundled enclave (`signer-with-enclave`)

The `signer-with-enclave` target bundles a real Enclave Image File (EIF). Building the EIF only requires the `nitro-cli` binary — **a Nitro-Enclaves-enabled EC2 host is not needed to build an EIF**; that is only required to run an enclave.

1. Install `nitro-cli` by following the official AWS guide: https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html

2. Create a `docker-container` builder. The enclave bake target uses `rewrite-timestamp=true` for reproducible builds, which requires the `docker-container` driver (BuildKit >= 0.13.0):

   ```bash
   docker buildx create --name enclave-builder --driver docker-container --use
   ```

3. Run the end-to-end build:

   ```bash
   # 1. Build the enclave Docker image
   docker buildx bake --provenance=false --allow fs.read=./docker/certs enclave

   # 2. Package the Docker image into an EIF
   nitro-cli build-enclave \
     --docker-uri nitro-enclave-signer/enclave:latest \
     --output-file enclave.eif

   # 3. Bundle the EIF into the final signer-with-enclave image
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

> **Note:** The attestation condition lives in the **KMS key policy** above — it is not required in the EC2 IAM role policy. The IAM role authorizes the temporary credentials passed to the enclave-owned KMS client; the key policy then requires those KMS requests to carry valid enclave attestation.

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

The signer only writes to Secrets Manager during **first-run key generation**: when the configured secret has no stored value, the host calls `GenerateKey` and persists the wrapped key with `secretsmanager:PutSecretValue` (see [Key Generation Flow](#key-generation-flow)). Once a non-empty secret exists, every subsequent startup **loads** that envelope and never calls `GenerateKey` or `PutSecretValue` — steady-state operation needs read access only.

Because the long-running host proxy is untrusted, `secretsmanager:PutSecretValue` **must not remain available during steady-state operation**. Grant write access only for the bootstrap run, confirm the key was stored, then switch to a read-only runtime role. Use two least-privilege policies, each scoped to the specific KMS key ARN and validator secret ARN — never `*`.

**Bootstrap policy (first-run only).** Attach this to a bootstrap role or temporary write-policy phase used for the initial generation run. It permits `GetSecretValue` and `PutSecretValue` on the exact validator secret.

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
      "Sid": "SecretsManagerValidatorKeyBootstrap",
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

**Runtime policy (steady-state).** After bootstrap completes, the host runs under this policy. It is identical to the bootstrap policy except that the Secrets Manager statement drops `PutSecretValue`, leaving read-only access.

> **Example only — replace the placeholders as above.**

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
      "Sid": "SecretsManagerValidatorKeyRuntime",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:000000000000:secret:arc-chain/dev/validator-1/key-*"
    }
  ]
}
```

The trailing `-*` on the secret ARN is required because Secrets Manager appends a random 6-character suffix to each secret's full ARN.

**Multi-region keys:** if you created a multi-region KMS key and replicated it to additional regions, add one `Resource` ARN per replica to the `KMSEnvelopeOps` statement in both policies. For example:

```json
"Resource": [
  "arn:aws:kms:us-east-1:000000000000:key/mrk-EXAMPLE-KEY-ID-1234-5678",
  "arn:aws:kms:us-west-2:000000000000:key/mrk-EXAMPLE-KEY-ID-1234-5678"
]
```

Each replica key also requires its own key policy with the attestation condition (the PCR0 value is the same across regions for the same EIF).

#### Bootstrap-to-runtime permission lifecycle

Perform these steps once per validator secret, in order. The goal is to leave the long-running host with read-only Secrets Manager access.

1. **Bootstrap run.** Deploy the signer under the bootstrap policy. On first run the empty secret triggers `GenerateKey`, and the host writes the wrapped key with `PutSecretValue`.
2. **Confirm the wrapped key was stored.** Before removing write access, verify the secret now holds a non-empty value — for example, `aws secretsmanager get-secret-value --secret-id arc-chain/dev/validator-1/key --query SecretString --output text` returns the base64 envelope. Do not proceed until this succeeds.
3. **Switch to the runtime role.** Move the host to the runtime policy (drop `PutSecretValue`), and **invalidate the bootstrap access**: remove, expire, or explicitly revoke the bootstrap role/session so its write permission can no longer be assumed.
4. **Verify write access is gone.** Under the runtime role, confirm `secretsmanager:PutSecretValue` on the validator secret returns `AccessDenied` (for example, a `put-secret-value` call is rejected). A successful denial confirms a compromised host proxy can no longer overwrite or evict the recoverable validator key.

An existing non-empty secret makes startup load the key without calling `GenerateKey` or `PutSecretValue`, so restarts and redeployments under the runtime role need no write access.

#### Wiring it up

Once the resources above exist, point the signer at them by setting:

- `APP_PROVIDER_AWSKMS_ARNS` — the KMS key ARN (or comma-separated list for multi-region)
- `APP_SERVICE_SIGNER_KEYID` — the Secrets Manager secret name or ARN

See [Common Production Settings](#common-production-settings) below for the settings most commonly needed in production.

### Common Production Settings

The service uses [Viper](https://github.com/spf13/viper) for configuration management with the following precedence (highest to lowest):

1. Environment variables
2. Configuration file
3. Default values

Application settings loaded through Viper use the `APP_` prefix. Nested keys use
underscores in environment variable names. For example,
`provider.awskms.arns` maps to `APP_PROVIDER_AWSKMS_ARNS`. The production build
applies its security policy after Viper loads the settings. This policy enables
Nitro, sets the VSOCK CID and ports, and disables LocalStack. In the production
build, `APP_ENV=stg` is only a deployment label. The environment label does not
select runtime behavior. The production AWS client ignores configured endpoint
overrides. Standard observability variables configure the host only. The
launcher does not send these variables to the EIF.

The production images do not set a default AWS Region. Set `AWS_REGION` before
you start the signer. You can also set the region in a standard AWS shared
configuration file. The host reads the region from the AWS configuration.
During initialization, the host sends the region to the enclave. The production
endpoint policy ignores endpoint overrides. The AWS client continues to use the
region.

The production launcher does not set `APP_PUBLIC_SERVER_PORT`. The packaged
production configuration file sets the default port to `10340`. Set
`APP_PUBLIC_SERVER_PORT` to use a different port.

```bash
# Required - AWS configuration
export AWS_REGION=us-east-1
export APP_PROVIDER_AWSKMS_ARNS=arn:aws:kms:us-east-1:000000000000:key/EXAMPLE-KEY-ID-1234-5678
# APP_SERVICE_SIGNER_KEYID accepts either the secret name or its full ARN.
export APP_SERVICE_SIGNER_KEYID=arc-chain/dev/validator-1/key

# Enclave configuration
# Only signer-dev uses ENABLE_ENCLAVE. The production launcher always starts Nitro.
# A host binary with the prod build tag uses VSOCK CID 16 and port 10350.
# APP_PROVIDER_ENCLAVE_NITROENCLAVE_CID and
# APP_PROVIDER_ENCLAVE_NITROENCLAVE_PORT cannot change this target.

# Service configuration
export APP_PUBLIC_SERVER_PORT=10340
export APP_PUBLIC_SERVER_TLS_ENABLED=true
export APP_PUBLIC_SERVER_TLS_CERT=/etc/tls/server.crt
export APP_PUBLIC_SERVER_TLS_KEY=/etc/tls/server.key
# Optional mTLS client authentication. Enable only after Malachite and every
# health probe using port 10340 have trusted client certificates.
# export APP_PUBLIC_SERVER_TLS_CLIENTAUTH_ENABLED=true
# export APP_PUBLIC_SERVER_TLS_CLIENTAUTH_CA=/etc/tls/client-ca.crt
export APP_PROFILER_ENABLED=false

# Host observability (optional)
# Traces use the standard OpenTelemetry endpoint variable.
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317
export DD_AGENT_HOST=localhost
export DD_SERVICE=arc-signer
export DD_ENV=prod

# Prometheus metrics (optional, disabled by default)
export APP_METRICS_PROMETHEUS_ENABLED=true
export APP_METRICS_PROMETHEUS_HOST=0.0.0.0
export APP_METRICS_PROMETHEUS_PORT=9090
export APP_METRICS_PROMETHEUS_PATH=/metrics
```

`APP_PROVIDER_SECRETS_LOCALSTACK_REGION` is a development/LocalStack setting and is not the production AWS region selector. The public gRPC listener is plaintext by default. Enabling the server certificate settings provides server-authenticated TLS; enabling client authentication additionally requires certificates issued by the configured client CA. Client authentication fails startup when TLS is disabled or the CA path is missing, unreadable, empty, or not composed entirely of valid PEM-encoded X.509 certificates. The application verifies CA membership rather than a specific SAN or SPIFFE identity, so the client CA must be dedicated to authorized Malachite workloads.

Client authentication covers every service on the public listener, including the gRPC health service. Before enabling it, configure Malachite and every health probe that uses port 10340 to present a trusted client certificate. Roll out the client identity and probe support before requiring client certificates on the server; otherwise the fail-closed handshake will make signing and health checks unavailable. This setting does not authenticate callers of the enclave's port 10350 TCP/VSOCK API.

Example config file (`configs/app.yaml`):

```yaml
provider:
  awskms:
    arns: arn:aws:kms:us-east-1:000000000000:key/EXAMPLE-KEY-ID-1234-5678

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

When running the image directly with Docker, the host must have Nitro Enclaves
enabled and enough CPU and memory configured in the Nitro Enclaves allocator.
Pass `/dev/nitro_enclaves` into the container and use a seccomp profile that
allows `AF_VSOCK` (the smoke test uses `--security-opt seccomp=unconfined`).
Expose port `10340` with normal Docker port publishing or host networking; host
networking is not itself a Nitro Enclaves requirement.

On Kubernetes, request the Nitro Enclaves device resource and sufficient
hugepage memory for the configured enclave size. The production docker-arc
deployment requests one `aws.ec2.nitro/nitro_enclaves` device and 4 GiB of
1 GiB hugepages. Its seccomp policy must also allow `AF_VSOCK`; regular pod
networking can expose port `10340`, so `hostNetwork` is not required.

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
| `PublicKey` | _(empty)_ | `public_key`, `attestation_document` |
| `Sign` | `message bytes` | `signature bytes` |

**EnclaveService** (internal, port 10350 over TCP in dev/CI or VSOCK in Nitro production):

| Method | Request | Response |
|--------|---------|----------|
| `Initialize` | AWS credentials, KMS key ARNs, LocalStack selector | _(empty)_ |
| `GenerateKey` | `algorithm` | `public_key`, `secret_envelope` |
| `GetPublicKey` | `secret_envelope` | `public_key`, `attestation_document` |
| `SignMessage` | `secret_envelope`, `message` | `signature` |

`secret_envelope` is the wrapped key: `{ algorithm, kms_encrypted_data_key, encrypted_private_key, nonce }`. The enclave mints it on `GenerateKey` and the host relays it back on the read RPCs; the enclave KMS-decrypts it in-enclave. For full field definitions see the proto files listed above.

### Error Handling

| Code | Meaning | Common Causes |
|------|---------|---------------|
| `OK (0)` | Success | — |
| `INVALID_ARGUMENT (3)` | Bad request | Missing or malformed message payload, unknown algorithm |
| `PERMISSION_DENIED (7)` | KMS rejected the request | Invalid IAM/KMS permissions or attestation policy mismatch |
| `FAILED_PRECONDITION (9)` | Not initialized | KMS provider not ready; `Initialize` has not completed |
| `INTERNAL (13)` | Server error | Uninitialized service state, enclave key unwrap/decryption error, signing failure |
| `UNAVAILABLE (14)` | Dependency unavailable | Enclave transport failure, retryable KMS failure, or expired public key attestation |

Secrets Manager is accessed during service initialization. Its failures prevent startup rather than returning a public signer RPC status.

## Troubleshooting

### Common Issues

Service fails with enclave connection error:

- Verify enclave is running: `nitro-cli describe-enclaves`
- Verify that the enclave CID is `16`
- Inspect enclave logs: `nitro-cli console --enclave-id <id>`

Unexpected signing latency:

- Startup `GenerateKey` or `GetPublicKey` loads the enclave key cache.
- Steady-state signing does not call KMS or Secrets Manager.
- Signer initialization calls NSM in Nitro mode. A background task calls NSM again before the public key attestation certificate expires.
- For sustained latency, inspect traces and enclave logs. When `APP_PROFILER_ENABLED=true`, inspect the Datadog continuous profiler output

AWS permission errors:

- Verify IAM role permissions for KMS/Secrets Manager
- Verify region and target resource IDs

Proto mismatch issues:

- Regenerate protos: `make proto`
- Rebuild host/enclave binaries

### Debugging

For enclave-focused debugging:

- `nitro-cli console --enclave-id <id>`
- `nitro-cli describe-enclaves`
