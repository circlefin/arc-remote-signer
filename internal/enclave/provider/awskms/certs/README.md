# Amazon Trust Roots

The enclave uses `amazon-trust-roots.pem` as the exclusive root pool for TLS
connections to AWS KMS in production. The bundle contains these self-signed
certificates:

- Amazon Root CA 1
- Amazon Root CA 2
- Amazon Root CA 3
- Amazon Root CA 4
- Starfield Services Root Certificate Authority - G2

The certificates come from the
[Amazon Trust Services repository](https://www.amazontrust.com/repository/).
The direct source files are:

- `https://www.amazontrust.com/repository/AmazonRootCA1.pem`
- `https://www.amazontrust.com/repository/AmazonRootCA2.pem`
- `https://www.amazontrust.com/repository/AmazonRootCA3.pem`
- `https://www.amazontrust.com/repository/AmazonRootCA4.pem`
- `https://www.amazontrust.com/repository/SFSRootCAG2.pem`

Amazon publishes these certificate files under the
[Creative Commons Attribution-NoDerivatives 4.0 International License](https://creativecommons.org/licenses/by-nd/4.0/).
The bundle concatenates the source files without modifying the certificates.

## Certificate verification

Before you update the bundle, verify the SHA-256 hash of each DER certificate:

```sh
openssl x509 -in AmazonRootCA1.pem -outform DER | sha256sum
```

`approvedAmazonRootCAFingerprints` contains the approved hashes from the Amazon
repository. The runtime parser rejects a certificate if it is added, removed,
duplicated, or replaced.

## KMS chain fixture

The test fixture at `../testdata/kms-us-east-1-chain.pem` contains the leaf
certificate and the intermediate certificate. AWS KMS served the certificate
chain on September 4, 2026. The chain test uses a time when the leaf certificate
is valid. The selected time keeps the test result the same after the leaf
certificate expires. The fixture is not part of the trusted root pool.

## Root rotation

1. Review the Amazon Trust Services repository for announced root changes.
2. Download each new certificate from the official HTTPS location.
3. Verify the DER hash against the value that Amazon publishes.
4. Before you remove a retiring root, add each new root.
5. Update `amazonRootCACount` for the temporary number of trusted roots.
6. Add each new fingerprint to `approvedAmazonRootCAFingerprints` and
   `expectedFingerprints`.
7. Run the provider tests for AWS KMS and all repository tests.
8. Build the new enclave image.
9. Record the PCR measurements for the new enclave image.
10. Add the new PCR measurements to each applicable KMS policy.
11. Keep the previous PCR measurements in each policy.
12. Deploy the new enclave image.
13. Verify that the new enclave can use each configured KMS key.
14. Deployment gate: before AWS's announced activation or start-serving date
    for the new root, confirm that every replica runs this EIF, its PCR
    measurement is authorized by the applicable KMS policies, and KMS access
    has been verified. If this gate cannot be completed by that date, treat
    production readiness as blocked and escalate before AWS begins serving the
    new chain.
15. After all replicas use the new image, remove the previous PCR measurements.
16. Wait until AWS completes the root migration.
17. Remove the retiring root from the bundle.
18. Update `amazonRootCACount`, `approvedAmazonRootCAFingerprints`, and
    `expectedFingerprints`.
19. Repeat steps 7 through 15 for the reduced root bundle.

Do not add leaf certificates or intermediate certificates to this bundle.
