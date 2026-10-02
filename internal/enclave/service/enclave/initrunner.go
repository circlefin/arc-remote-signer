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

	"github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awskms"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// runInit builds a candidate Ready state without publishing partial state.
func (s *Service) runInit(ctx context.Context, req *pb.InitializeRequest) (*readyState, error) {
	awsCfg, err := awskms.BuildConfig(req.Credentials, s.awsproxyEndpoint, req.KmsLocalstackEnabled)
	if err != nil {
		return nil, fmt.Errorf("build aws config: %w", err)
	}
	pvd, err := s.kmsFactory(ctx, awsCfg, req.KmsKeyArns)
	if err != nil {
		return nil, fmt.Errorf("build kms provider: %w", err)
	}

	var (
		key       crypto.Key
		publicKey []byte
		envelope  *pb.SecretEnvelope
	)
	switch source := req.GetKeySource().(type) {
	case *pb.InitializeRequest_ExistingKey:
		key, err = s.loadKeyCandidate(ctx, pvd, source.ExistingKey)
		if err != nil {
			return nil, err
		}
		publicKey, err = key.PublicKey()
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to get public key")
		}
	case *pb.InitializeRequest_GenerateNew:
		envelope, key, publicKey, err = s.generateEnvelopeCandidate(ctx, pvd, source.GenerateNew)
		if err != nil {
			return nil, err
		}
	default:
		return nil, status.Error(codes.InvalidArgument, "key_source is required")
	}

	var attestationDocument []byte
	if s.nitroEnclaveEnabled {
		if s.enclavePvd == nil {
			return nil, status.Error(codes.Internal, "enclave provider is nil while nitro enclave is enabled")
		}
		attestationDocument, err = s.enclavePvd.Attest(publicKey)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to attest public key")
		}
	}

	return &readyState{
		key: key,
		response: &pb.InitializeResponse{
			PublicKey:           publicKey,
			AttestationDocument: attestationDocument,
			SecretEnvelope:      envelope,
		},
	}, nil
}
