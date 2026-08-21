// Copyright (c) 2026, Circle Internet Group, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package enclave

import (
	"context"
	"fmt"

	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awskms"
	"github.com/circlefin/arc-remote-signer/proto/pb"
)

// runInit is the callback the init gate invokes on the first successful
// Initialize call. It builds an AWS KMS client through awsproxy from the
// host-supplied credentials, retains it on the Service for the read/generate
// RPCs (which run right after Initialize while the credentials are fresh, so
// no credential refresh is needed), and exercises a GenerateDataKey
// reachability + credential probe.
//
// A LocalStack request uses s.awsproxyEndpoint as the SDK base endpoint.
// A standard AWS KMS request leaves the base endpoint unchanged and uses
// end-to-end TLS. See awskms.BuildConfig for the contract.
//
// GenerateDataKey exercises the full path from credentials to the KMS backend
// through awsproxy. Nitro requests include RecipientInfo with attestation.
func (s *Service) runInit(ctx context.Context, req *pb.InitializeRequest) error {
	awsCfg, err := awskms.BuildConfig(req.Credentials, s.awsproxyEndpoint, req.KmsLocalstackEnabled)
	if err != nil {
		return fmt.Errorf("build aws config: %w", err)
	}
	pvd, err := s.kmsFactory(ctx, awsCfg, req.KmsKeyArns)
	if err != nil {
		return fmt.Errorf("build kms provider: %w", err)
	}
	// Reachability + credential probe; the return values are discarded. In
	// dev/CI the factory builds the KMS client without an attestation
	// document, so KMS returns the plaintext directly; in production the
	// client is built with a RecipientInfo (attestation), so KMS omits the
	// plaintext and returns only CiphertextForRecipient. The probe discards
	// that ciphertext; normal key operations decrypt it in this process with
	// the in-memory RSA private key corresponding to the attested public key.
	if _, _, _, err = pvd.GenerateDataKey(ctx); err != nil {
		return fmt.Errorf("kms generate data key probe: %w", err)
	}
	// Retain the client only after the probe validates the credentials, so
	// GenerateKey/GetPublicKey/SignMessage never see an unvalidated provider.
	s.setKMSProvider(pvd)
	return nil
}
