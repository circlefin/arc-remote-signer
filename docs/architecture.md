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

On startup, the host reads the configured secret from Secrets Manager. The host
asks the enclave to recover the stored key or generate a new key. The host
retrieves temporary AWS credentials for each `Initialize` attempt. The host
refreshes the credentials after an authentication failure. The host sends the
credentials, KMS key ARNs, LocalStack selector, and key source in the request.

Each enclave attempt requests a fresh KMS Recipient attestation in Nitro mode.
The attempt creates an ephemeral KMS provider and completes the key transaction.
The transaction generates or recovers the signing key and creates a public key
attestation. The enclave publishes the Ready state only after the complete
transaction succeeds. A failed attempt does not install a key.

```
Host application                    Enclave                    NSM / AWS KMS
       │                                │                            │
       │── read stored envelope         │                            │
       │── retrieve credentials         │                            │
       │── Initialize(key source, ─────▶│                            │
       │     credentials, KMS settings) │── fresh recipient attest ─▶│
       │                                │── generate or recover key ─▶│
       │                                │── attest public key ───────▶│
       │                                │── publish Ready             │
       │◀─ public key, attestation, ─────│                            │
       │   optional generated envelope  │                            │
       │── persist generated envelope   │                            │
  [ready to serve requests]
```

### Key Generation Flow

Key generation is triggered when the configured, pre-created Secrets Manager secret has no stored key value:

1. The host calls Enclave `Initialize` with `generate_new` set to the configured algorithm.
2. The enclave creates an ephemeral KMS provider for the attempt. In Nitro mode, the provider uses a fresh KMS Recipient attestation.
3. The enclave calls KMS `GenerateDataKey`. KMS returns `CiphertextForRecipient` in Nitro mode, and the enclave decrypts it with its in-memory RSA private key. KMS returns the plaintext data key in dev/CI.
4. The enclave generates the signing keypair and encrypts the private key with AES-GCM. It creates `SecretEnvelope { algorithm, kms_encrypted_data_key, encrypted_private_key, nonce }`.
5. In Nitro mode, the enclave creates an attestation document for the public key.
6. The enclave installs the signing key and publishes the Ready state.
7. The enclave returns the public key, attestation document, and generated envelope. The host maps the envelope to a stored `Header` and writes it to Secrets Manager.

```
Host application      Enclave              NSM / AWS KMS          Secrets Manager
       │                  │                       │                         │
       │── Initialize ───▶│                       │                         │
       │   (generate_new) │── GenerateDataKey ───▶│                         │
       │                  │◀─ ciphertext blobs ───│                         │
       │                  │  enclave decrypts data key and wraps signing key│
       │                  │── enclave requests public-key attestation ─▶│   │
       │                  │◀─ NSM returns attestation document ─│            │
       │                  │  enclave publishes Ready                         │
       │◀─ key + document │                       │                         │
       │   + envelope     │                       │                         │
       │── PutSecret(Header from envelope) ────────────────────────────────▶│
       │                  │                       │                         │
```

The host persists a generated `SecretEnvelope`. It keeps the public key and its
attestation document in memory. Only enclave memory contains the plaintext
private key and plaintext data key.

### Signing Flow

After successful initialization, signing uses only the installed enclave key:

1. The host sends only the message to Enclave `SignMessage`.
2. The enclave signs the message with the installed key.
3. The enclave returns the signature.

```
Validator          Host application       Enclave
    │                      │                  │
    │── Sign(msg) ────────▶│                  │
    │                      │── SignMessage ──▶│
    │                      │   (message only) │── sign with installed key
    │                      │◀─ signature ─────│
    │◀─ signature ─────────│                  │
```

Steady-state signing does not send the envelope and does not call KMS or
Secrets Manager.

### Public Key Attestation Flow

During signer initialization, Enclave `Initialize` returns the installed public
key and its attestation document. In Nitro mode, the enclave asks NSM to create
the document before it publishes the Ready state. The signed `user_data` field
contains the exact public key bytes. The host keeps the public key and document
in memory. It also reads the earliest certificate expiry from the document.
The background refresh process uses Enclave `GetPublicKey` to create a later
attestation document for the installed key.

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
    │                      │── Initialize ───▶│                       │
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

The enclave independently requires the credentials region and every KMS ARN
region to appear in its compiled AWS commercial KMS region allowlist. Unknown
values and non-commercial partitions are rejected before any endpoint, TLS
server name, proxy route, or SDK client is constructed. When AWS adds a region
to the [KMS endpoints reference](https://docs.aws.amazon.com/general/latest/gr/kms.html),
the enclave validator and its positive region test must be updated together.
The resulting EIF has new PCR measurements, so deploying it also requires the
normal image release and KMS key policy rollout.

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

Attestation binds recovery of KMS-protected data keys to an approved enclave release on an authorized parent EC2 instance. KMS key policies enforce PCR0, PCR1, PCR2, and PCR4 conditions. KMS encrypts successful responses to the attested enclave key. Host credentials alone cannot recover plaintext data keys on another host.

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

### Using and Building Images

#### Circle-published production image

Circle publishes the tested production image to Cloudsmith. See
[Reproducible Enclave Builds](../README.md#reproducible-enclave-builds) for the
registry location. The linked section explains how Circle delivers the image to
partners.

Use the supplied token to log in to Cloudsmith. Use the supplied image reference
to pull the image. Record the image digest after the pull:

```bash
docker pull docker.cloudsmith.io/circle/arc/arc-remote-signer:<version>
docker image inspect \
  --format '{{ index .RepoDigests 0 }}' \
  docker.cloudsmith.io/circle/arc/arc-remote-signer:<version>
```

Use the recorded digest in the deployment configuration. Read the PCR0, PCR1,
and PCR2 values from the labels on the pulled image. Configure the KMS key
policy with the PCR0, PCR1, and PCR2 values and the calculated parent instance
PCR4 value. You do not have to build an EIF when you use the Circle-published
image.

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

#### Custom production image with bundled enclave (`signer-with-enclave`)

The `signer-with-enclave` target bundles a real Enclave Image File (EIF). Building the EIF only requires the `nitro-cli` binary — **a Nitro-Enclaves-enabled EC2 host is not needed to build an EIF**; that is only required to run an enclave.

Use the following commands only if you build a custom image from the public
source code. Record the measured PCR values (PCR0, PCR1, and PCR2). If you
publish the custom image, record the registry digest after publication.
Configure the KMS key policy with the measured PCR0, PCR1, and PCR2 values and
the calculated parent instance PCR4 value.

1. Use the official AWS guide to install `nitro-cli`: https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html

2. Create a `docker-container` builder. The `enclave` target for
   `docker buildx bake` uses `rewrite-timestamp=true` to create a reproducible
   build. This option requires the `docker-container` driver and BuildKit 0.13.0
   or later:

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

   # 3. Record the PCR values
   nitro-cli describe-eif \
     --eif-path enclave.eif \
     > describe_eif.json

   PCR0="$(jq -er '.Measurements.PCR0' describe_eif.json)"
   PCR1="$(jq -er '.Measurements.PCR1' describe_eif.json)"
   PCR2="$(jq -er '.Measurements.PCR2' describe_eif.json)"

   # 4. Bundle the EIF and PCR labels into the final custom image
   docker buildx bake \
     --set "signer-with-enclave.args.ENCLAVE_EIF=./enclave.eif" \
     --set "signer-with-enclave.args.ENCLAVE_PCR0=${PCR0}" \
     --set "signer-with-enclave.args.ENCLAVE_PCR1=${PCR1}" \
     --set "signer-with-enclave.args.ENCLAVE_PCR2=${PCR2}" \
     signer-with-enclave
   ```

> [!NOTE]
> Different versions of `nitro-cli` can change the EIF build measurements even
> when the application code is identical. Pin `nitro-cli` to a specific version.
> For every new EIF, record PCR0, PCR1, and PCR2 again and coordinate any KMS key
> policy updates before deployment.

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

The signer uses **envelope encryption**: a symmetric AWS KMS key wraps a per-validator data key, which encrypts the validator private key stored in Secrets Manager.

- Create a **symmetric** key with key spec `SYMMETRIC_DEFAULT`. **Asymmetric and RSA keys are not supported.**
- A **multi-region** key is recommended — `APP_PROVIDER_AWSKMS_ARNS` accepts multiple ARNs and the signer fails over across them.
- The policy must allow `kms:Decrypt` and `kms:GenerateDataKey` only when `kms:RecipientAttestation:PCR0`, `PCR1`, `PCR2`, and `PCR4` match the approved enclave release and parent EC2 instance.

##### Enclave measurements and identity

AWS Nitro Enclaves attestation provides cryptographic measurements in Platform Configuration Registers (PCRs):

- **PCR0**: SHA-384 hash of the Enclave Image File (EIF).
- **PCR1**: SHA-384 hash of the Linux kernel and bootstrap ramfs.
- **PCR2**: SHA-384 hash of the user applications.
- **PCR4**: SHA-384 hash of the parent EC2 instance ID.

PCR0, PCR1, and PCR2 establish the approved enclave release identity. PCR4 establishes the deployment identity of the parent EC2 instance. Requiring all four measurements prevents an attacker who compromises the host from copying credentials and ciphertexts to decrypt validator keys on another EC2 instance.

##### Obtaining and calculating PCR values

For the Circle-published image, use the digest that you recorded in
[Circle-published production image](#circle-published-production-image). Read
the PCR labels from that exact digest:

```bash
docker image inspect \
  --format $'PCR0: {{ index .Config.Labels "enclave.pcr0" }}\nPCR1: {{ index .Config.Labels "enclave.pcr1" }}\nPCR2: {{ index .Config.Labels "enclave.pcr2" }}' \
  docker.cloudsmith.io/circle/arc/arc-remote-signer@sha256:<digest-value>
```

For a custom image, record the PCR values from the build output or run `describe-eif`:

```bash
nitro-cli describe-eif \
  --eif-path enclave.eif \
  > describe_eif.json

PCR0="$(jq -er '.Measurements.PCR0' describe_eif.json)"
PCR1="$(jq -er '.Measurements.PCR1' describe_eif.json)"
PCR2="$(jq -er '.Measurements.PCR2' describe_eif.json)"
```

Calculate the `PCR4` measurement for the parent EC2 instance. `PCR4` is the SHA-384 hash of 48 null bytes (`\x00` * 48) followed by the UTF-8 instance ID string (for example, `i-0123456789abcdef0`):

```bash
# Retrieve instance ID via IMDSv2
TOKEN="$(curl -s -S -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")"
INSTANCE_ID="$(curl -s -S -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)"

# Calculate the SHA-384 PCR4 measurement
python3 -c 'import hashlib, sys; h=hashlib.sha384(b"\x00"*48 + sys.argv[1].encode("utf-8")); print(h.hexdigest())' "$INSTANCE_ID"
```

Use the measured PCR0, PCR1, and PCR2 values and the calculated PCR4 value in the KMS key policy. Do not use measurements from an unverified build or a different instance.

##### Canonical key policy

The following key policy uses six controls:

1. A dedicated administration role can manage the key. This policy does not
   authorize the role to call `Decrypt`, `GenerateDataKey`, or `CreateGrant`.
2. Explicit `Deny` statements reject data-key requests that omit any required
   measurement (`PCR0`, `PCR1`, `PCR2`, or `PCR4`).
3. Explicit `Deny` statements reject data-key requests containing unexpected
   measurements. Each measurement has a separate `Deny` statement with a
   `StringNotEqualsIgnoreCase` condition. Do not combine negative conditions
   into a single statement. A combined negative condition can permit unexpected
   access if condition semantics evaluate partially.
4. The policy denies `CreateGrant`. The signer does not need grants. Without
   this denial, an existing KMS grant can authorize new access.
5. The policy denies `ReEncryptFrom`. Without this denial, a caller can rewrap a
   stored encrypted data key under a key that the host controls. The `ReEncrypt`
   API has no `Recipient` parameter.
6. A separate `Allow` statement authorizes the signer host role only when the
   request contains matching `PCR0`, `PCR1`, `PCR2`, and `PCR4` measurements.

Use the complete policy when you create the primary key. Do not use the AWS
default policy. While the default policy is active, an IAM policy can authorize
a data-key request that has no recipient attestation.

The principal that creates a key must have `kms:CreateKey` in its IAM policy.
This requirement applies in the primary region and each replica region. A key
policy cannot authorize `kms:CreateKey`.

> **Example only. Replace both role ARNs. Replace the account ID. Replace the
> PCR placeholders with your recorded measurements.**
>
> Do not authorize the AWS account principal to call `kms:*`. If the key policy
> authorizes the AWS account principal to call `kms:*`, IAM policies can
> authorize requests without attestation.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowKeyAdministration",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::000000000000:role/arc-signer-key-admin"
      },
      "Action": [
        "kms:CancelKeyDeletion",
        "kms:DescribeKey",
        "kms:DisableKey",
        "kms:DisableKeyRotation",
        "kms:EnableKey",
        "kms:EnableKeyRotation",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListGrants",
        "kms:PutKeyPolicy",
        "kms:ReplicateKey",
        "kms:RevokeGrant",
        "kms:ScheduleKeyDeletion",
        "kms:UpdateKeyDescription",
        "kms:UpdatePrimaryRegion"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyDataKeyOperationsWithoutPCR0",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
      "Condition": {
        "Null": {
          "kms:RecipientAttestation:PCR0": "true"
        }
      }
    },
    {
      "Sid": "DenyDataKeyOperationsWithoutPCR1",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
      "Condition": {
        "Null": {
          "kms:RecipientAttestation:PCR1": "true"
        }
      }
    },
    {
      "Sid": "DenyDataKeyOperationsWithoutPCR2",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
      "Condition": {
        "Null": {
          "kms:RecipientAttestation:PCR2": "true"
        }
      }
    },
    {
      "Sid": "DenyDataKeyOperationsWithoutPCR4",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
      "Condition": {
        "Null": {
          "kms:RecipientAttestation:PCR4": "true"
        }
      }
    },
    {
      "Sid": "DenyDataKeyOperationsForUnexpectedPCR0",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": "TRUSTED_PCR0_FOR_SELECTED_IMAGE_DIGEST"
        }
      }
    },
    {
      "Sid": "DenyDataKeyOperationsForUnexpectedPCR1",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR1": "TRUSTED_PCR1_FOR_SELECTED_IMAGE_DIGEST"
        }
      }
    },
    {
      "Sid": "DenyDataKeyOperationsForUnexpectedPCR2",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR2": "TRUSTED_PCR2_FOR_SELECTED_IMAGE_DIGEST"
        }
      }
    },
    {
      "Sid": "DenyDataKeyOperationsForUnexpectedPCR4",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR4": "TRUSTED_PCR4_FOR_PARENT_INSTANCE_ID"
        }
      }
    },
    {
      "Sid": "DenyGrantCreation",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "kms:CreateGrant",
      "Resource": "*"
    },
    {
      "Sid": "DenyReEncryptFrom",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "kms:ReEncryptFrom",
      "Resource": "*"
    },
    {
      "Sid": "AllowAttestedDataKeyOperations",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::000000000000:role/arc-signer-host"
      },
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": "TRUSTED_PCR0_FOR_SELECTED_IMAGE_DIGEST",
          "kms:RecipientAttestation:PCR1": "TRUSTED_PCR1_FOR_SELECTED_IMAGE_DIGEST",
          "kms:RecipientAttestation:PCR2": "TRUSTED_PCR2_FOR_SELECTED_IMAGE_DIGEST",
          "kms:RecipientAttestation:PCR4": "TRUSTED_PCR4_FOR_PARENT_INSTANCE_ID"
        }
      }
    }
  ]
}
```

References:

- [Using cryptographic attestation with AWS KMS](https://docs.aws.amazon.com/enclaves/latest/user/kms.html)
- [AWS KMS Nitro Enclaves condition keys](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html)
- [Grants in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/grants.html)
- [ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html)

The IAM policy for the EC2 host does not need permissions for KMS data-key
operations. Do not add a key policy statement that authorizes `Decrypt` or
`GenerateDataKey` without recipient attestation. Do not add a KMS grant that
authorizes these operations. Do not authorize `ReEncryptFrom` on the signer key.
The policy denies `CreateGrant` for every principal. The signer key does not need
grants. Do not authorize the signer host role to call `kms:PutKeyPolicy`. Do not
authorize the signer host role to assume the key administration role. The key
administration role can change the key policy. Protect the key administration
role. Preserve an approved method to recover administrative access to the key.

When you update a key policy, AWS KMS does not delete existing grants. Before
production use, assume the key administration role. List the grants for the
primary key and every replica:

```bash
aws kms list-grants \
  --key-id "$KEY_ARN" \
  --region "$REGION"
```

Revoke each grant that includes `Decrypt`, `GenerateDataKey`, `ReEncryptFrom`,
or `CreateGrant`. The signer does not need grants for these operations. Run the
following command for each grant that you must revoke:

```bash
aws kms revoke-grant \
  --key-id "$KEY_ARN" \
  --grant-id "$GRANT_ID" \
  --region "$REGION"
```

Run `list-grants` again. Record the result. The explicit denies prevent an
existing grant from authorizing the denied operations. You must still remove
each grant that permits a denied operation.

##### Multi-region replication

Apply the complete policy to the primary key and each multi-region replica key.
The release measurements (PCR0, PCR1, and PCR2) are identical across all regions
for the same EIF. The deployment measurement (PCR4) is identical across regions
because it binds to the parent EC2 instance. Add the ARN for a replica to
`APP_PROVIDER_AWSKMS_ARNS` only after all tests for that replica pass.

##### Instance replacement procedure

Follow these steps to replace the parent EC2 instance without service interruption:

1. **Launch the new instance**:
   Launch a new EC2 instance with Nitro Enclaves enabled.
   Record the instance ID of the new instance.

2. **Calculate the new PCR4 measurement**:
   Calculate the PCR4 measurement for the new instance ID.

3. **Update key policies across all regions**:
   Update the KMS key policy on the primary key and all replica keys.
   Add the new PCR4 measurement to `AllowAttestedDataKeyOperations`:
   ```json
   "kms:RecipientAttestation:PCR4": [
     "OLD_PCR4_VALUE",
     "NEW_PCR4_VALUE"
   ]
   ```
   Update `DenyDataKeyOperationsForUnexpectedPCR4` to allow both values during cutover:
   ```json
   "StringNotEqualsIgnoreCase": {
     "kms:RecipientAttestation:PCR4": [
       "OLD_PCR4_VALUE",
       "NEW_PCR4_VALUE"
     ]
   }
   ```

4. **Deploy and validate the signer**:
   Deploy the approved signer release on the new EC2 instance.
   Start the signer container.
   Verify that the signer reads the validator key from Secrets Manager and KMS.
   Verify that health probes pass.

5. **Cut over and stop the old signer**:
   Route validator traffic to the new signer.
   Use the trusted EC2 control plane to stop the old instance, and wait until
   the instance reaches the `stopped` state. Verify that the old signer no
   longer accepts requests. Do not rely on an in-guest shutdown when the old
   host might be compromised.

   Removing the old PCR4 measurement does not stop a running enclave. The old
   enclave can continue signing with the validator key already cached in its
   memory without calling KMS again.

6. **Remove the old PCR4 measurement**:
   Update the KMS key policy across all regions.
   Remove the old PCR4 measurement from `AllowAttestedDataKeyOperations` and `DenyDataKeyOperationsForUnexpectedPCR4`.
   Verify that only the new PCR4 measurement remains authorized.

   This is the final rollback window for the old instance. To roll back, use
   the trusted EC2 control plane to stop the new instance and wait until it
   reaches the `stopped` state. Verify that the new signer no longer accepts
   requests. Restore the old PCR4 measurement to the key policies across all
   regions, restart and validate the old signer, and then route validator
   traffic back to it. Never run both signers at the same time with the same
   validator key.

7. **Terminate the old instance**:
   Terminate the stopped EC2 instance. Termination is irreversible. Any later
   rollback requires launching another instance and authorizing its new PCR4
   measurement.

##### Incident guidance for suspected host compromise

If you suspect an attacker compromised the parent host before you enforced PCR4:

1. **Begin validator key rotation immediately**:
   Adding PCR4 to the key policy does not protect a key that an attacker already
   recovered. If an attacker copied temporary credentials and decrypted the
   data key, the attacker can sign messages outside your infrastructure. Treat
   the old validator key as compromised.

2. **Create an isolated replacement environment**:
   Deploy a fresh EC2 instance with a new signer host role. Provision a new KMS
   key, including any required multi-region replicas, and apply the complete
   PCR0, PCR1, PCR2, and new-instance PCR4 policy to every key. Do not reuse the
   old secret, KMS key, or host role for the replacement validator.

3. **Generate and verify the new validator key**:
   Generate a new validator signing key in the new enclave and store its
   encrypted envelope in a new Secrets Manager secret protected by the new KMS
   key. Restart the new signer to clear its enclave memory. Verify that it can
   recover the new validator key and sign after restart using only the new
   secret, KMS key, and host role.

4. **Replace the compromised public key on-chain**:
   Submit the protocol-specific transaction that replaces or revokes the old
   validator public key; registering an additional key is not sufficient if
   the old key remains authorized. Wait for the transaction to reach the
   required finality. Verify that signatures from the new key are accepted and
   signatures from the old key are rejected.

5. **Stop and terminate the compromised host**:
   Use the trusted EC2 control plane to stop the compromised instance. Verify
   that the old signer no longer accepts requests, and then terminate the
   instance. Do not rely on an in-guest shutdown.

6. **Retire the old AWS recovery path**:
   Confirm that the replacement signer and all other workloads do not depend on
   the old secret, KMS key, or host role. Delete the old secret, revoke the old
   role sessions and permissions, and remove the old PCR4 measurement from all
   old KMS key policies. Disable an old KMS key only after confirming that no
   remaining workload uses it. These actions prevent future recovery of the old
   validator key, but the on-chain replacement in the previous step is what
   invalidates a copy that an attacker already recovered.

##### AWS key policy validation tests

Before production use, run the following positive and negative tests against the key policy:

1. **Positive test (Approved EIF on authorized instance)**:
   Start the approved EIF on the authorized parent EC2 instance.
   Verify that `kms:GenerateDataKey` and `kms:Decrypt` succeed through the attested enclave.

2. **Negative test (Unauthorized parent instance / stolen credentials)**:
   Copy the temporary IAM role credentials and encrypted secret envelope to a different EC2 instance.
   Start the same approved EIF on that different EC2 instance.
   Verify that KMS rejects the request with `AccessDeniedException` because PCR4 does not match.

3. **Negative test (Modified enclave image)**:
   Start an unapproved or modified EIF on the authorized EC2 instance.
   Verify that KMS rejects the request with `AccessDeniedException` because PCR0, PCR1, or PCR2 does not match.

4. **Negative test (Missing recipient attestation)**:
   Make a `kms:Decrypt` or `kms:GenerateDataKey` request directly from the host without recipient attestation.
   Verify that KMS rejects the request with `AccessDeniedException`.

5. **Negative test (Unauthorized grant or re-encryption)**:
   Call `CreateGrant` for the signer key. Verify that KMS rejects the request
   with `AccessDeniedException` because the key policy denies
   `kms:CreateGrant`.

   Call the `ReEncrypt` API with a ciphertext encrypted under the signer key as
   the source and a test-controlled KMS key as the destination. Verify that KMS
   rejects the request with `AccessDeniedException` because the signer key
   policy denies the required `kms:ReEncryptFrom` permission.

6. **Multi-Region validation**:
   Repeat these tests for every multi-region replica key.

7. **Auditor evidence**:
   Collect and record the following evidence for security auditors:
   - The active KMS key policy document for the primary key and all replicas (`aws kms get-key-policy`).
   - AWS CloudTrail event logs showing `AccessDeniedException` for all negative test attempts and success for authorized operations.
   - The immutable Git commit SHA of the approved release.

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

The signer writes to Secrets Manager only during **first-run key generation**.
During this run, the configured secret has no stored value. The host calls
`Initialize` with `generate_new` and persists the wrapped key with
`secretsmanager:PutSecretValue` (see [Key Generation Flow](#key-generation-flow)).
Once a non-empty secret exists, every subsequent startup calls `Initialize`
with `existing_key` and does not call `PutSecretValue`. Steady-state operation
needs read access only.

Remove `secretsmanager:PutSecretValue` permission after bootstrap because the
long-running host proxy is untrusted. Authorize write access for the bootstrap run
only. Confirm that the host stored the key. Then use a runtime role with
read-only access. Use two least-privilege IAM policies. Scope both policies to
the validator secret ARN. The KMS key policy allows `Decrypt` and
`GenerateDataKey` only for requests with valid recipient attestation.

**Bootstrap policy (first run only).** Attach the bootstrap policy to a dedicated
bootstrap role. Alternatively, attach the bootstrap policy to the runtime role
only for the first key-generation run. The bootstrap policy permits
`GetSecretValue` and `PutSecretValue` on the specified validator secret.

> **Example only. Replace the account ID and secret name with your own values.**

```json
{
  "Version": "2012-10-17",
  "Statement": [
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

#### Bootstrap-to-runtime permission lifecycle

Perform these steps once per validator secret, in order. The goal is to leave the long-running host with read-only Secrets Manager access.

1. **Bootstrap run.** Deploy the signer under the bootstrap policy. On first run, the empty secret makes the host call `Initialize` with `generate_new`. The host writes the returned wrapped key with `PutSecretValue`.
2. **Confirm the wrapped key was stored.** Before removing write access, verify the secret now holds a non-empty value — for example, `aws secretsmanager get-secret-value --secret-id arc-chain/dev/validator-1/key --query SecretString --output text` returns the base64 envelope. Do not proceed until this succeeds.
3. **Switch to the runtime role.** Move the host to the runtime policy (drop `PutSecretValue`), and **invalidate the bootstrap access**: remove, expire, or explicitly revoke the bootstrap role/session so its write permission can no longer be assumed.
4. **Verify write access is gone.** Under the runtime role, confirm `secretsmanager:PutSecretValue` on the validator secret returns `AccessDenied` (for example, a `put-secret-value` call is rejected). A successful denial confirms a compromised host proxy can no longer overwrite or evict the recoverable validator key.

An existing non-empty secret makes the host call `Initialize` with `existing_key`. Restarts and redeployments do not call `PutSecretValue`, so the runtime role needs no write access.

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
| `Initialize` | AWS credentials, KMS key ARNs, LocalStack selector, and one key source: `existing_key` or `generate_new` | `public_key`, `attestation_document`, and `secret_envelope` only for a generated key |
| `GenerateKey` | `algorithm` | Returns `FAILED_PRECONDITION`. Use `Initialize` to generate a key. |
| `GetPublicKey` | _(empty)_ | Installed `public_key`, `attestation_document` |
| `SignMessage` | `message` | `signature` |

`secret_envelope` is the wrapped key: `{ algorithm, kms_encrypted_data_key, encrypted_private_key, nonce }`. `Initialize` returns it when the enclave generates a key. The host persists it in Secrets Manager. On a later startup, the host sends it as `existing_key` in `Initialize`, and the enclave recovers the key. `GenerateKey` and `GetPublicKey` remain in the internal API for compatibility, but they are not the initialization path. For full field definitions, see the proto files listed above.

### Error Handling

| Code | Meaning | Common Causes |
|------|---------|---------------|
| `OK (0)` | Success | — |
| `INVALID_ARGUMENT (3)` | Bad request | Missing or malformed message payload, unknown algorithm |
| `PERMISSION_DENIED (7)` | KMS rejected the request | Invalid IAM/KMS permissions or attestation policy mismatch |
| `FAILED_PRECONDITION (9)` | Operation requires the Ready state | `Initialize` has not completed, `GenerateKey` was called directly, or the enclave already has a different key source |
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

- Verify that startup `Initialize` completed. It generates or recovers the key and installs it in the enclave.
- Steady-state signing uses the installed key. It does not call KMS or Secrets Manager.
- In Nitro mode, `Initialize` calls NSM for KMS Recipient attestation and public key attestation. A background task calls NSM again before the certificate for the public-key attestation expires.
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
