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

// Package v1 implements the version 1 signer service and key lifecycle.
package v1

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/circlefin/arc-remote-signer/internal/app/provider/secrets"
	"github.com/circlefin/arc-remote-signer/internal/common/crypto"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_loggerLoadOnce sync.Once
	_logger         *logging.Logger
)

func getLogger() *logging.Logger {
	_loggerLoadOnce.Do(func() {
		_logger = logging.Get("service.signer")
	})
	return _logger
}

const (
	errSignMessage            = "failed to sign message"
	errInvalidRequest         = "invalid request"
	errEmptyMessage           = "message cannot be empty"
	errServiceNotInitialized  = "service is not initialized"
	errAttestationExpired     = "attestation document is expired"
	errAttestationNotValidYet = "attestation certificate is not valid yet"
)

// Service is the implementation of the Signer gRPC server.
type Service struct {
	pb.UnimplementedSignerServiceServer
	enclavePvd  pb.EnclaveServiceClient
	loadedKeyMu sync.RWMutex
	loadedKey   *keyState
}

// InitializeKeyFunc installs or recovers the enclave key.
type InitializeKeyFunc func(
	context.Context,
	*pb.SecretEnvelope,
	pb.Algorithm,
) (*pb.InitializeResponse, error)

// keyState contains public response data for the installed enclave key.
type keyState struct {
	publicKey           []byte
	attestationDocument []byte
	attestationValidity attestationValidity
}

// New creates a new instance of the Signer gRPC server.
//
// The enclave creates an ephemeral KMS client for each initialization attempt.
// It completes key generation or recovery before it publishes the Ready state.
// The host persists a generated SecretEnvelope and does not call KMS directly.
func New(
	ctx context.Context,
	keyCfg *Config,
	secretPvd secrets.Provider,
	enclavePvd pb.EnclaveServiceClient,
	initializeKey InitializeKeyFunc,
) (*Service, error) {
	pbAlgorithm, err := toPBAlgorithm(keyCfg.Algorithm)
	if err != nil {
		return nil, err
	}
	if initializeKey == nil {
		return nil, errors.New("enclave initializer is required")
	}
	loadedKey, err := initializeKeyState(ctx, keyCfg, secretPvd, pbAlgorithm, initializeKey)
	if err != nil {
		return nil, err
	}
	service := &Service{
		enclavePvd: enclavePvd,
		loadedKey:  loadedKey,
	}
	service.startAttestationRefresh(ctx)
	return service, nil
}

func initializeKeyState(
	ctx context.Context,
	keyCfg *Config,
	secretPvd secrets.Provider,
	algorithm pb.Algorithm,
	initializeKey InitializeKeyFunc,
) (*keyState, error) {
	secret, err := secretPvd.Get(ctx, keyCfg.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	if len(secret) == 0 {
		return generateAndStoreKey(ctx, keyCfg, secretPvd, algorithm, initializeKey)
	}

	return loadKeyFromSecret(ctx, secret, algorithm, initializeKey)
}

func generateAndStoreKey(
	ctx context.Context,
	keyCfg *Config,
	secretPvd secrets.Provider,
	algorithm pb.Algorithm,
	initializeKey InitializeKeyFunc,
) (*keyState, error) {
	resp, err := initializeKey(ctx, nil, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize generated key: %w", err)
	}
	if resp == nil || resp.SecretEnvelope == nil {
		return nil, errors.New("enclave Initialize returned no secret envelope")
	}
	if len(resp.PublicKey) == 0 {
		return nil, errors.New("enclave Initialize returned empty public key")
	}
	env := resp.SecretEnvelope
	if env.Algorithm != algorithm {
		return nil, fmt.Errorf("generated key algorithm %s does not match configured algorithm %s", env.Algorithm, algorithm)
	}
	if len(env.GetKmsEncryptedDataKey()) == 0 || len(env.GetEncryptedPrivateKey()) == 0 || len(env.GetNonce()) == 0 {
		return nil, errors.New("enclave Initialize returned incomplete secret envelope")
	}

	headerBytes, err := headerFromSecretEnvelope(resp.SecretEnvelope).MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}
	loadedKey, err := newKeyState(resp)
	if err != nil {
		return nil, err
	}

	if _, err := secretPvd.Update(ctx, keyCfg.KeyID, headerBytes); err != nil {
		return nil, fmt.Errorf("failed to update secret: %w", err)
	}

	getLogger().Info(ctx, "loaded signer public key", logging.Entries{"public_key": "0x" + hex.EncodeToString(resp.PublicKey)})
	return loadedKey, nil
}

func loadKeyFromSecret(
	ctx context.Context,
	secret []byte,
	algorithm pb.Algorithm,
	initializeKey InitializeKeyFunc,
) (*keyState, error) {
	hdr := header{}
	if err := hdr.UnmarshalBinary(secret); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	// The stored header records the algorithm the key was generated under. Fail
	// cleanly on a config/key mismatch instead of silently signing under the
	// wrong algorithm. Secrets written before this field decode as
	// ALGORITHM_UNSPECIFIED and fall through to the configured algorithm.
	if hdr.Algorithm != pb.Algorithm_ALGORITHM_UNSPECIFIED && hdr.Algorithm != algorithm {
		return nil, fmt.Errorf("stored key algorithm %s does not match configured algorithm %s", hdr.Algorithm, algorithm)
	}

	envelope := hdr.toSecretEnvelope(algorithm)
	resp, err := initializeKey(ctx, envelope, pb.Algorithm_ALGORITHM_UNSPECIFIED)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize existing key: %w", err)
	}
	if resp == nil {
		return nil, errors.New("enclave Initialize returned no response")
	}
	if resp.SecretEnvelope != nil {
		return nil, errors.New("enclave Initialize returned an envelope for an existing key")
	}

	loadedKey, err := newKeyState(resp)
	if err != nil {
		return nil, err
	}

	getLogger().Info(ctx, "loaded signer public key", logging.Entries{"public_key": "0x" + hex.EncodeToString(resp.PublicKey)})
	return loadedKey, nil
}

func newKeyState(resp *pb.InitializeResponse) (*keyState, error) {
	if resp == nil || len(resp.PublicKey) == 0 {
		return nil, errors.New("enclave Initialize returned empty public key")
	}
	var validity attestationValidity
	if len(resp.AttestationDocument) > 0 {
		parsedValidity, err := parseAttestationValidity(resp.AttestationDocument)
		if err != nil {
			return nil, fmt.Errorf("failed to parse attestation document: %w", err)
		}
		if err := parsedValidity.validateAt(time.Now()); err != nil {
			return nil, err
		}
		validity = parsedValidity
	}

	return &keyState{
		publicKey:           bytes.Clone(resp.PublicKey),
		attestationDocument: bytes.Clone(resp.AttestationDocument),
		attestationValidity: validity,
	}, nil
}

func (s *Service) refreshAttestation(ctx context.Context) (attestationValidity, error) {
	s.loadedKeyMu.RLock()
	if s.loadedKey == nil {
		s.loadedKeyMu.RUnlock()
		return attestationValidity{}, errors.New(errServiceNotInitialized)
	}
	publicKey := bytes.Clone(s.loadedKey.publicKey)
	currentValidity := s.loadedKey.attestationValidity
	s.loadedKeyMu.RUnlock()

	resp, err := s.getPublicKey(ctx)
	if err != nil {
		return currentValidity, err
	}
	if !bytes.Equal(publicKey, resp.PublicKey) {
		return currentValidity, errors.New("enclave returned a different public key")
	}
	if len(resp.AttestationDocument) == 0 {
		return currentValidity, errors.New("enclave returned an empty attestation document")
	}
	validity, err := parseAttestationValidity(resp.AttestationDocument)
	if err != nil {
		return currentValidity, fmt.Errorf("failed to parse attestation document: %w", err)
	}
	if err := validity.validateAt(time.Now()); err != nil {
		return currentValidity, err
	}
	if !validity.notAfter.After(currentValidity.notAfter) {
		return currentValidity, nil
	}

	s.loadedKeyMu.Lock()
	if s.loadedKey != nil && bytes.Equal(s.loadedKey.publicKey, publicKey) {
		s.loadedKey.attestationDocument = bytes.Clone(resp.AttestationDocument)
		s.loadedKey.attestationValidity = validity
	}
	s.loadedKeyMu.Unlock()
	return validity, nil
}

func (s *Service) startAttestationRefresh(ctx context.Context) {
	s.loadedKeyMu.RLock()
	if s.loadedKey == nil || s.loadedKey.attestationValidity.notAfter.IsZero() {
		s.loadedKeyMu.RUnlock()
		return
	}
	validity := s.loadedKey.attestationValidity
	s.loadedKeyMu.RUnlock()

	go s.runAttestationRefresh(ctx, validity)
}

func (s *Service) runAttestationRefresh(ctx context.Context, validity attestationValidity) {
	retry := false
	for {
		delay := attestationRefreshDelay(time.Now(), validity, retry)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-timer.C:
		}

		refreshedValidity, err := s.refreshAttestation(ctx)
		if err != nil {
			getLogger().ErrorErr(ctx, "failed to refresh attestation document", err, nil)
			retry = true
			continue
		}
		retry = !refreshedValidity.notAfter.After(validity.notAfter)
		validity = refreshedValidity
	}
}

func (s *Service) getPublicKey(ctx context.Context) (*pb.GetPublicKeyResponse, error) {
	resp, err := s.enclavePvd.GetPublicKey(ctx, &pb.GetPublicKeyRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}
	if resp == nil || len(resp.PublicKey) == 0 {
		return nil, errors.New("enclave GetPublicKey returned empty public key")
	}
	return resp, nil
}

// PublicKey returns the cached key and a valid attestation document.
func (s *Service) PublicKey(_ context.Context, _ *pb.PublicKeyRequest) (*pb.PublicKeyResponse, error) {
	s.loadedKeyMu.RLock()
	defer s.loadedKeyMu.RUnlock()
	if s.loadedKey == nil {
		return nil, status.Error(codes.Internal, errServiceNotInitialized)
	}
	if !s.loadedKey.attestationValidity.notAfter.IsZero() {
		if err := s.loadedKey.attestationValidity.validateAt(time.Now()); err != nil {
			return nil, status.Error(codes.Unavailable, err.Error())
		}
	}

	return &pb.PublicKeyResponse{
		PublicKey:           bytes.Clone(s.loadedKey.publicKey),
		AttestationDocument: bytes.Clone(s.loadedKey.attestationDocument),
	}, nil
}

// Sign validates the request, signs the message through the enclave provider,
// and returns the generated signature.
// It returns gRPC status errors for invalid input and uninitialized service state.
func (s *Service) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	// Validate request
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, errInvalidRequest)
	}
	if len(req.Message) == 0 {
		return nil, status.Error(codes.InvalidArgument, errEmptyMessage)
	}

	s.loadedKeyMu.RLock()
	if s.loadedKey == nil {
		s.loadedKeyMu.RUnlock()
		return nil, status.Error(codes.Internal, errServiceNotInitialized)
	}
	s.loadedKeyMu.RUnlock()

	// call the enclave to sign the message
	resp, err := s.enclavePvd.SignMessage(ctx, &pb.SignMessageRequest{
		Message: req.Message,
	})
	if err != nil {
		getLogger().ErrorErr(ctx, errSignMessage, err, nil)
		return nil, status.Error(codes.Internal, errSignMessage)
	}
	// Convert the response back to protobuf format
	return &pb.SignResponse{
		Signature: resp.Signature,
	}, nil
}

func toPBAlgorithm(algorithm crypto.Algorithm) (pb.Algorithm, error) {
	switch algorithm {
	case crypto.AlgorithmBLS:
		return pb.Algorithm_ALGORITHM_BLS, nil
	case crypto.AlgorithmEd25519:
		return pb.Algorithm_ALGORITHM_ED25519, nil
	default:
		return pb.Algorithm_ALGORITHM_UNSPECIFIED, fmt.Errorf("unknown algorithm: %s", algorithm)
	}
}
