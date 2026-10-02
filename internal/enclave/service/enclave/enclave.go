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

// Package enclave implements enclave cryptographic gRPC service handlers.
package enclave

import (
	"context"
	"errors"

	enclaveCrypto "github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awskms"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/enclave"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Service implements the enclave gRPC service handlers.
type Service struct {
	pb.UnimplementedEnclaveServiceServer
	nitroEnclaveEnabled bool
	enclavePvd          enclave.Provider
	kmsFactory          awskms.Factory
	awsproxyEndpoint    string
	gate                *initGate
}

func (s *Service) activeKey() (enclaveCrypto.Key, error) {
	if s.gate == nil {
		return nil, status.Error(codes.FailedPrecondition, "enclave is not initialized")
	}
	state := s.gate.state()
	if state == nil || state.key == nil {
		return nil, status.Error(codes.FailedPrecondition, "enclave is not initialized")
	}
	return state.key, nil
}

// New creates a new enclave service instance. Each initialization attempt
// creates an ephemeral KMS client through awsproxyEndpoint. The attempt
// completes key generation or recovery before it publishes the Ready state.
//
// nitroEnclaveEnabled controls the proxy transport and the KMS TLS strategy.
// Standard AWS KMS keeps the AWS endpoint and uses end-to-end TLS. LocalStack
// uses awsproxyEndpoint as the SDK base endpoint and uses plain HTTP. The
// Initialize request selects the KMS backend. Nitro mode rejects LocalStack.
func New(
	nitroEnclaveEnabled bool,
	enclavePvd enclave.Provider,
	awskmsFactory awskms.Factory,
	awsproxyEndpoint string,
) *Service {
	s := &Service{
		nitroEnclaveEnabled: nitroEnclaveEnabled,
		enclavePvd:          enclavePvd,
		kmsFactory:          awskmsFactory,
		awsproxyEndpoint:    awsproxyEndpoint,
	}
	s.gate = newInitGate(s.runInit)
	return s
}

// newWithGate is the test-friendly constructor that lets tests inject a
// custom runInit callback (e.g. one that fails) without exposing a
// settable field on Service after construction. Production code uses New.
//
// Callers must keep nitroEnclaveEnabled consistent with the runInit callback.
// New derives both values from the same flag, but this test seam accepts them
// independently.
func newWithGate(
	nitroEnclaveEnabled bool,
	enclavePvd enclave.Provider,
	runInit func(context.Context, *pb.InitializeRequest) error,
) *Service {
	wrappedRunInit := func(ctx context.Context, req *pb.InitializeRequest) (*readyState, error) {
		if err := runInit(ctx, req); err != nil {
			return nil, err
		}
		return &readyState{
			response: &pb.InitializeResponse{PublicKey: []byte("test-public-key")},
		}, nil
	}
	return &Service{
		nitroEnclaveEnabled: nitroEnclaveEnabled,
		enclavePvd:          enclavePvd,
		gate:                newInitGate(wrappedRunInit),
	}
}

// Initialize completes one key transaction. Concurrent calls share one
// attempt. After success, matching requests receive cloned responses. An
// existing-key request can replay the envelope from a successful generation
// response. Other key sources fail. A failed attempt does not publish the
// Ready state, and a later call can retry.
//
// Each attempt creates an ephemeral AWS KMS client through the injected
// factory. The attempt uses the client only for key generation or recovery.
//
// Note: AwsCredentials fields arrive as proto-generated strings, which
// Go cannot zero out. Documenting the limitation here; switching the
// proto field to bytes (or adopting a Zeroize-style wrapper) is a
// follow-up improvement.
func (s *Service) Initialize(ctx context.Context, req *pb.InitializeRequest) (*pb.InitializeResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is nil")
	}
	if req.Credentials == nil {
		return nil, status.Error(codes.InvalidArgument, "credentials are required")
	}
	if len(req.KmsKeyArns) == 0 {
		return nil, status.Error(codes.InvalidArgument, "kms_key_arns is required")
	}
	if s.nitroEnclaveEnabled && req.KmsLocalstackEnabled {
		return nil, status.Error(codes.InvalidArgument, "LocalStack is not available in Nitro mode")
	}
	// Validate every host-supplied region before the idempotence gate. Invalid
	// retries must not inherit the result of an earlier successful request.
	if err := awskms.ValidateRegions(req.Credentials.Region, req.KmsKeyArns); err != nil {
		return nil, runInitStatusError(err)
	}
	fingerprint, err := fingerprintKeySource(req)
	if err != nil {
		return nil, err
	}
	resp, err := s.gate.ensureInitialized(ctx, req, fingerprint)
	if err != nil {
		return nil, runInitStatusError(err)
	}
	return resp, nil
}

// toStatusError maps a raw KMS or enclave SDK error to a gRPC status, preserving any
// code the inner call already chose. Context cancellation/deadline take
// precedence so client disconnects are not mis-classified as Internal;
// recognized KMS errors are mapped via awskms.StatusFromError; errors that
// already carry a gRPC status are passed through unchanged; everything else
// becomes Internal. The original message is preserved so operators can see
// what went wrong (host and enclave are the same trust boundary).
//
// A non-empty prefix is prepended to the mapped KMS status and the Internal
// fallback for call-site context (e.g. "kms decrypt data key"). Context codes
// are left unprefixed since they are self-explanatory.
func toStatusError(prefix string, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, err.Error())
	}
	// An invalid KMS ARN or credentials region is client input. Classify these
	// errors as InvalidArgument instead of using the Internal fallback.
	if errors.Is(err, awskms.ErrInvalidARN) || errors.Is(err, awskms.ErrInvalidRegion) {
		if prefix == "" {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		return status.Errorf(codes.InvalidArgument, "%s: %v", prefix, err)
	}
	if mapped := awskms.StatusFromError(err); mapped != err {
		if prefix == "" {
			return mapped
		}
		st := status.Convert(mapped)
		return status.Errorf(st.Code(), "%s: %s", prefix, st.Message())
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	if prefix == "" {
		return status.Error(codes.Internal, err.Error())
	}
	return status.Errorf(codes.Internal, "%s: %v", prefix, err)
}

// runInitStatusError maps a runInit error to a gRPC status. It shares
// toStatusError with the envelope path (kmsStatusError) so the Initialize and
// read/generate RPCs surface context/KMS errors identically. runInit is the
// only caller and returns raw (fmt.Errorf-wrapped) errors — unlike
// generateEnvelope, which returns straight to its RPC and so maps to a status
// itself via kmsStatusError — so this is the single mapping point for the
// Initialize path and no prefix is added here.
func runInitStatusError(err error) error {
	return toStatusError("", err)
}

// GenerateKey is disabled. Initialize is the only operation that can install a
// signing key.
func (s *Service) GenerateKey(_ context.Context, req *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is nil")
	}
	if _, err := toAlgorithm(req.Algorithm); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return nil, status.Error(codes.FailedPrecondition, "key generation is available only through Initialize")
}

// GetPublicKey returns and attests the installed Ready-state key.
func (s *Service) GetPublicKey(_ context.Context, _ *pb.GetPublicKeyRequest) (*pb.GetPublicKeyResponse, error) {
	secretKey, err := s.activeKey()
	if err != nil {
		return nil, err
	}

	publicKey, err := secretKey.PublicKey()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get public key")
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

	return &pb.GetPublicKeyResponse{
		PublicKey:           publicKey,
		AttestationDocument: attestationDocument,
	}, nil
}

// SignMessage signs with the installed Ready-state key.
func (s *Service) SignMessage(_ context.Context, req *pb.SignMessageRequest) (*pb.SignMessageResponse, error) {
	secretKey, err := s.activeKey()
	if err != nil {
		return nil, err
	}

	signature, err := secretKey.SignMessage(req.Message)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to sign message")
	}

	return &pb.SignMessageResponse{
		Signature: signature,
	}, nil
}
