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
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awskms"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/keystore"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Service implements the enclave gRPC service handlers.
type Service struct {
	pb.UnimplementedEnclaveServiceServer
	nitroEnclaveEnabled bool
	keystore            keystore.Provider
	enclavePvd          enclave.Provider
	kmsFactory          awskms.Factory
	awsproxyEndpoint    string
	kmsMu               sync.RWMutex
	kmsPvd              awskms.Provider
	gate                *initGate
}

// kmsProvider returns the KMS provider retained at Initialize, or nil if
// Initialize has not run. The read/generate RPCs use it to decrypt or mint
// data keys in-enclave.
func (s *Service) kmsProvider() awskms.Provider {
	s.kmsMu.RLock()
	defer s.kmsMu.RUnlock()
	return s.kmsPvd
}

// setKMSProvider stores the KMS provider built during Initialize for reuse
// by the read/generate RPCs.
func (s *Service) setKMSProvider(p awskms.Provider) {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	s.kmsPvd = p
}

// New creates a new enclave service instance. The init gate's runInit
// callback exercises AWS KMS through awsproxyEndpoint when the host
// invokes Initialize, using the supplied factory to build an ephemeral
// KMS client.
//
// nitroEnclaveEnabled controls the proxy transport and the KMS TLS strategy.
// Standard AWS KMS keeps the AWS endpoint and uses end-to-end TLS. LocalStack
// uses awsproxyEndpoint as the SDK base endpoint and uses plain HTTP. The
// Initialize request selects the KMS backend. Nitro mode rejects LocalStack.
func New(
	nitroEnclaveEnabled bool,
	keystore keystore.Provider,
	enclavePvd enclave.Provider,
	awskmsFactory awskms.Factory,
	awsproxyEndpoint string,
) *Service {
	s := &Service{
		nitroEnclaveEnabled: nitroEnclaveEnabled,
		keystore:            keystore,
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
	keystore keystore.Provider,
	enclavePvd enclave.Provider,
	runInit runInitFunc,
) *Service {
	return &Service{
		nitroEnclaveEnabled: nitroEnclaveEnabled,
		keystore:            keystore,
		enclavePvd:          enclavePvd,
		gate:                newInitGate(runInit),
	}
}

// Initialize runs the enclave-side init gate. Concurrent Initialize
// calls collapse onto one execution; repeated calls after success are
// idempotent and return nil. A failed Initialize does not latch the
// gate, so the host can retry.
//
// The runInit callback builds an ephemeral AWS KMS client via the
// injected factory and exercises a single GenerateDataKey call to verify
// reachability of AWS KMS through awsproxy and that the host-supplied
// credentials authenticate.
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
	// Parse each ARN at the entry so malformed input surfaces as
	// InvalidArgument; awskms.New rejects it later as untyped Internal.
	for i, a := range req.KmsKeyArns {
		if _, err := arn.Parse(a); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid kms_key_arns[%d] %q: %s", i, a, err)
		}
	}
	if err := s.gate.ensureInitialized(ctx, req); err != nil {
		return nil, runInitStatusError(err)
	}
	return &pb.InitializeResponse{}, nil
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

// GenerateKey mints a new signing key in-enclave and returns its public key
// plus the SecretEnvelope the host persists to Secrets Manager.
func (s *Service) GenerateKey(ctx context.Context, req *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is nil")
	}
	env, publicKey, err := s.generateEnvelope(ctx, req.Algorithm)
	if err != nil {
		return nil, err
	}
	return &pb.GenerateKeyResponse{
		PublicKey:      publicKey,
		SecretEnvelope: env,
	}, nil
}

// GetPublicKey derives the public key from the request's SecretEnvelope,
// KMS-decrypting it in-enclave on a cache miss.
func (s *Service) GetPublicKey(ctx context.Context, req *pb.GetPublicKeyRequest) (*pb.GetPublicKeyResponse, error) {
	secretKey, err := s.loadKeyFromEnvelope(ctx, req.GetSecretEnvelope())
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

// SignMessage signs the request message with the key from the SecretEnvelope.
func (s *Service) SignMessage(ctx context.Context, req *pb.SignMessageRequest) (*pb.SignMessageResponse, error) {
	secretKey, err := s.loadKeyFromEnvelope(ctx, req.GetSecretEnvelope())
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
