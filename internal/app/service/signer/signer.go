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

//go:generate mockgen -source=signer.go -destination=signer_mock.go -package=signer . Service

// Package signer manages logic for avalanche-go external BLS signer
package signer

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
	secretPvd   secrets.Provider
	enclavePvd  pb.EnclaveServiceClient
	algorithm   pb.Algorithm
	loadedKeyMu sync.RWMutex
	loadedKey   *keyState
}

// keyState contains the envelope and the public response data. Initialization
// sets this state. The background refresh can replace the attestation data.
type keyState struct {
	secretEnvelope      *pb.SecretEnvelope
	publicKey           []byte
	attestationDocument []byte
	attestationValidity attestationValidity
}

// New creates a new instance of the Signer gRPC server.
//
// The host no longer performs any KMS work: the enclave owns key decryption
// (it retains its KMS client from the Initialize RPC, wired in app.Run before
// this constructor). The host only relays the wrapped SecretEnvelope.
func New(ctx context.Context, keyCfg *Config, secretPvd secrets.Provider, enclavePvd pb.EnclaveServiceClient) (*Service, error) {
	pbAlgorithm, err := toPBAlgorithm(keyCfg.Algorithm)
	if err != nil {
		return nil, err
	}
	service := &Service{
		secretPvd:  secretPvd,
		enclavePvd: enclavePvd,
		algorithm:  pbAlgorithm,
	}
	if err := service.initialize(ctx, keyCfg); err != nil {
		return nil, err
	}
	service.startAttestationRefresh(ctx)
	return service, nil
}

func (s *Service) initialize(ctx context.Context, keyCfg *Config) error {
	// retrieve the secret from the secret provider
	secret, err := s.secretPvd.Get(ctx, keyCfg.KeyID)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	if len(secret) == 0 {
		return s.generateAndStoreKey(ctx, keyCfg)
	}

	return s.loadKeyFromSecret(ctx, secret)
}

func (s *Service) generateAndStoreKey(ctx context.Context, keyCfg *Config) error {
	// First boot: no stored secret. The enclave mints a fresh data key
	// in-enclave (no host-supplied data key) and returns a self-contained
	// SecretEnvelope for us to persist verbatim to Secrets Manager.
	resp, err := s.enclavePvd.GenerateKey(ctx, &pb.GenerateKeyRequest{Algorithm: s.algorithm})
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	if resp.SecretEnvelope == nil {
		return errors.New("enclave GenerateKey returned no secret envelope")
	}
	if len(resp.PublicKey) == 0 {
		return errors.New("enclave GenerateKey returned empty public key")
	}
	// Validate the envelope is complete before the irreversible Secrets Manager
	// write. An incomplete envelope would be caught later when the enclave
	// tries to decrypt it, but only after it has already been persisted — every
	// subsequent boot would then fail against the corrupt secret.
	env := resp.SecretEnvelope
	if len(env.GetKmsEncryptedDataKey()) == 0 || len(env.GetEncryptedPrivateKey()) == 0 || len(env.GetNonce()) == 0 {
		return errors.New("enclave GenerateKey returned incomplete secret envelope")
	}

	headerBytes, err := headerFromSecretEnvelope(resp.SecretEnvelope).MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}
	publicKeyResp, err := s.getPublicKey(ctx, resp.SecretEnvelope)
	if err != nil {
		return err
	}
	if !bytes.Equal(resp.PublicKey, publicKeyResp.PublicKey) {
		return errors.New("enclave returned different public keys")
	}
	loadedKey, err := newKeyState(resp.SecretEnvelope, publicKeyResp)
	if err != nil {
		return err
	}

	if _, err := s.secretPvd.Update(ctx, keyCfg.KeyID, headerBytes); err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	s.storeLoadedKey(loadedKey)

	getLogger().Info(ctx, "loaded signer public key", logging.Entries{"public_key": "0x" + hex.EncodeToString(resp.PublicKey)})
	return nil
}

func (s *Service) loadKeyFromSecret(ctx context.Context, secret []byte) error {
	hdr := header{}
	if err := hdr.UnmarshalBinary(secret); err != nil {
		return fmt.Errorf("failed to unmarshal header: %w", err)
	}

	// The stored header records the algorithm the key was generated under. Fail
	// cleanly on a config/key mismatch instead of silently signing under the
	// wrong algorithm. Secrets written before this field decode as
	// ALGORITHM_UNSPECIFIED and fall through to the configured algorithm.
	if hdr.Algorithm != pb.Algorithm_ALGORITHM_UNSPECIFIED && hdr.Algorithm != s.algorithm {
		return fmt.Errorf("stored key algorithm %s does not match configured algorithm %s", hdr.Algorithm, s.algorithm)
	}

	// The enclave owns decryption now: hand it the stored envelope and let it
	// KMS-decrypt in-enclave. No host-side KMS Decrypt.
	envelope := hdr.toSecretEnvelope(s.algorithm)
	resp, err := s.getPublicKey(ctx, envelope)
	if err != nil {
		return err
	}

	loadedKey, err := newKeyState(envelope, resp)
	if err != nil {
		return err
	}
	s.storeLoadedKey(loadedKey)

	getLogger().Info(ctx, "loaded signer public key", logging.Entries{"public_key": "0x" + hex.EncodeToString(resp.PublicKey)})
	return nil
}

func newKeyState(envelope *pb.SecretEnvelope, resp *pb.GetPublicKeyResponse) (*keyState, error) {
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
		secretEnvelope:      envelope,
		publicKey:           bytes.Clone(resp.PublicKey),
		attestationDocument: bytes.Clone(resp.AttestationDocument),
		attestationValidity: validity,
	}, nil
}

func (s *Service) storeLoadedKey(loadedKey *keyState) {
	s.loadedKeyMu.Lock()
	s.loadedKey = loadedKey
	s.loadedKeyMu.Unlock()
}

func (s *Service) refreshAttestation(ctx context.Context) (attestationValidity, error) {
	s.loadedKeyMu.RLock()
	if s.loadedKey == nil {
		s.loadedKeyMu.RUnlock()
		return attestationValidity{}, errors.New(errServiceNotInitialized)
	}
	envelope := s.loadedKey.secretEnvelope
	publicKey := bytes.Clone(s.loadedKey.publicKey)
	currentValidity := s.loadedKey.attestationValidity
	s.loadedKeyMu.RUnlock()

	resp, err := s.getPublicKey(ctx, envelope)
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

func (s *Service) getPublicKey(ctx context.Context, envelope *pb.SecretEnvelope) (*pb.GetPublicKeyResponse, error) {
	resp, err := s.enclavePvd.GetPublicKey(ctx, &pb.GetPublicKeyRequest{SecretEnvelope: envelope})
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
	envelope := s.loadedKey.secretEnvelope
	s.loadedKeyMu.RUnlock()

	// call the enclave to sign the message
	resp, err := s.enclavePvd.SignMessage(ctx, &pb.SignMessageRequest{
		SecretEnvelope: envelope,
		Message:        req.Message,
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
