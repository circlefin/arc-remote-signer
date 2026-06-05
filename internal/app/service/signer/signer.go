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
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/circlefin/arc-remote-signer/internal/app/metrics"
	"github.com/circlefin/arc-remote-signer/internal/app/provider/awskms"
	"github.com/circlefin/arc-remote-signer/internal/app/provider/secrets"
	"github.com/circlefin/arc-remote-signer/internal/common/crypto"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/internal/common/metric"
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
	errSignMessage           = "failed to sign message"
	errInvalidRequest        = "invalid request"
	errEmptyMessage          = "message cannot be empty"
	errServiceNotInitialized = "service is not initialized"
)

// Service is the implementation of the Signer gRPC server.
type Service struct {
	pb.UnimplementedSignerServiceServer
	isNitroEnclaveEnabled bool
	secretPvd             secrets.Provider
	enclavePvd            pb.EnclaveServiceClient
	awskmsPvd             awskms.Provider
	algorithm             pb.Algorithm
	cache                 *cache
	prometheus            *metric.Prometheus
}

// New creates a new instance of the Signer gRPC server.
func New(ctx context.Context, isNitroEnclaveEnabled bool, keyCfg *Config, secretPvd secrets.Provider, enclavePvd pb.EnclaveServiceClient, awskmsPvd awskms.Provider, prometheus *metric.Prometheus) (*Service, error) {
	pbAlgorithm, err := toPBAlgorithm(keyCfg.Algorithm)
	if err != nil {
		return nil, err
	}
	service := &Service{
		isNitroEnclaveEnabled: isNitroEnclaveEnabled,
		secretPvd:             secretPvd,
		enclavePvd:            enclavePvd,
		awskmsPvd:             awskmsPvd,
		algorithm:             pbAlgorithm,
		cache:                 newCache(),
		prometheus:            prometheus,
	}
	if err := service.initialize(ctx, keyCfg); err != nil {
		return nil, err
	}
	return service, nil
}

func (s *Service) initialize(ctx context.Context, keyCfg *Config) error {
	// retrieve the secret from the secret provider
	secret, err := s.secretPvd.Get(ctx, keyCfg.KeyID)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	// if secret is empty, generate a new key, marshal it and store it in the cache
	if len(secret) == 0 {
		return s.generateAndStoreKey(ctx, keyCfg)
	}

	// if secret is not empty, derive the public key and store it in the cache
	return s.loadKeyFromSecret(ctx, secret)
}

func (s *Service) generateAndStoreKey(ctx context.Context, keyCfg *Config) error {
	/*
		Nitro is enabled in environments above CI/DEV, so the recipient parameter
		is included when calling AWS KMS. As a result, plainDataKey will be nil,
		so we don't need to zero it out here.
	*/
	plainDataKey, KMSEncryptedDataKey, enclaveEncryptedDataKey, err := s.awskmsPvd.GenerateDataKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate data key: %w", err)
	}

	pbAlgorithm, err := toPBAlgorithm(keyCfg.Algorithm)
	if err != nil {
		return err
	}

	extGenerateRequest := &pb.GenerateKeyRequest{
		Algorithm:               pbAlgorithm,
		EnclaveEncryptedDataKey: plainDataKey,
	}

	if enclaveEncryptedDataKey != nil {
		extGenerateRequest.EnclaveEncryptedDataKey = enclaveEncryptedDataKey
	}

	resp, err := s.enclavePvd.GenerateKey(ctx, extGenerateRequest)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	hdr := header{
		CipherKey:  KMSEncryptedDataKey,
		CipherData: resp.EncryptedPrivateKey,
		Nonce:      resp.Nonce,
	}

	headerBytes, err := hdr.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}

	if _, err := s.secretPvd.Update(ctx, keyCfg.KeyID, headerBytes); err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	s.cache.set(&key{
		encryptedKeyMaterial: prepareEncryptedKeyMaterial(s.isNitroEnclaveEnabled, resp.EncryptedPrivateKey, plainDataKey, enclaveEncryptedDataKey, resp.Nonce),
		publicKey:            resp.PublicKey,
	})

	getLogger().Info(ctx, "loaded signer public key", logging.Entries{"public_key": "0x" + hex.EncodeToString(resp.PublicKey)})
	return nil
}

func (s *Service) loadKeyFromSecret(ctx context.Context, secret []byte) error {
	hdr := header{}
	if err := hdr.UnmarshalBinary(secret); err != nil {
		return fmt.Errorf("failed to unmarshal header: %w", err)
	}

	/*
		Nitro is enabled in environments above CI/DEV, so the recipient parameter
		is included when calling AWS KMS. As a result, plainDataKey will be nil,
		so we don't need to zero it out here.
	*/
	plainDataKey, enclaveEncryptedDataKey, err := s.awskmsPvd.Decrypt(ctx, hdr.CipherKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt data key: %w", err)
	}

	encryptedKeyMaterial := prepareEncryptedKeyMaterial(s.isNitroEnclaveEnabled, hdr.CipherData, plainDataKey, enclaveEncryptedDataKey, hdr.Nonce)
	extGetPublicKeyRequest := &pb.GetPublicKeyRequest{
		Algorithm:            s.algorithm,
		EncryptedKeyMaterial: encryptedKeyMaterial,
	}

	resp, err := s.enclavePvd.GetPublicKey(ctx, extGetPublicKeyRequest)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	s.cache.set(&key{
		encryptedKeyMaterial: encryptedKeyMaterial,
		publicKey:            resp.PublicKey,
	})

	getLogger().Info(ctx, "loaded signer public key", logging.Entries{"public_key": "0x" + hex.EncodeToString(resp.PublicKey)})
	return nil
}

// PublicKey returns the cached signer public key.
// It returns a gRPC internal error when the service has not been initialized.
func (s *Service) PublicKey(_ context.Context, _ *pb.PublicKeyRequest) (*pb.PublicKeyResponse, error) {
	s.increment(metrics.RequestTotalCounter, "publickey")
	cached := s.cache.get()
	if cached == nil {
		s.increment(metrics.RequestTotalCounterError, "publickey")
		return nil, status.Error(codes.Internal, errServiceNotInitialized)
	}
	s.increment(metrics.RequestTotalCounterSuccess, "publickey")
	return &pb.PublicKeyResponse{
		PublicKey: cached.publicKey,
	}, nil
}

// Sign validates the request, signs the message through the enclave provider,
// and returns the generated signature.
// It returns gRPC status errors for invalid input and uninitialized service state.
func (s *Service) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	// Validate request
	s.increment(metrics.RequestTotalCounter, "sign")
	if req == nil {
		s.increment(metrics.RequestTotalCounterError, "sign")
		return nil, status.Error(codes.InvalidArgument, errInvalidRequest)
	}
	if len(req.Message) == 0 {
		s.increment(metrics.RequestTotalCounterError, "sign")
		return nil, status.Error(codes.InvalidArgument, errEmptyMessage)
	}

	cached := s.cache.get()
	if cached == nil {
		s.increment(metrics.RequestTotalCounterError, "sign")
		return nil, status.Error(codes.Internal, errServiceNotInitialized)
	}

	// call the enclave to sign the message
	resp, err := s.enclavePvd.SignMessage(ctx, &pb.SignMessageRequest{
		Algorithm:            s.algorithm,
		EncryptedKeyMaterial: cached.encryptedKeyMaterial,
		Message:              req.Message,
	})
	if err != nil {
		s.increment(metrics.RequestTotalCounterError, "sign")
		getLogger().ErrorErr(ctx, errSignMessage, err, nil)
		// Preserve the original gRPC status code from the enclave
		if st, ok := status.FromError(err); ok {
			return nil, st.Err()
		}
		// Fallback to Internal if not a gRPC status error
		return nil, status.Error(codes.Internal, errSignMessage)
	}
	// Convert the response back to protobuf format
	s.increment(metrics.RequestTotalCounterSuccess, "sign")
	return &pb.SignResponse{
		Signature: resp.Signature,
	}, nil
}

func prepareEncryptedKeyMaterial(isNitroEnclaveEnabled bool, encryptedPrivateKey, plainDataKey, enclaveEncryptedDataKey, nonce []byte) *pb.EncryptedKeyMaterial {
	// When we use the ricipient(attestation document) parameter, instead of returning the plaintext data, KMS
	// encrypts the plaintext data with the public key in the attestation document,
	// and returns the resulting ciphertext in the CiphertextForRecipient field
	// in the response. This ciphertext can be decrypted only with the private key
	// in the enclave. The Plaintext field in the response is null or empty.
	// So we use the `isNitroEnclaveEnabled` flag to determine whether to use the enclave encrypted data key or the plaintext data key.
	// If we use the plaintext data key with Nitro Enclave, it will cause the decryption failure.
	//
	// For more details, please refer to the following document:
	// https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html
	if isNitroEnclaveEnabled {
		return newEncryptedKeyMaterial(encryptedPrivateKey, enclaveEncryptedDataKey, nonce)
	}
	return newEncryptedKeyMaterial(encryptedPrivateKey, plainDataKey, nonce)
}

func newEncryptedKeyMaterial(encryptedPrivateKey, dataKey, nonce []byte) *pb.EncryptedKeyMaterial {
	material := &pb.EncryptedKeyMaterial{
		EncryptedPrivateKey:     encryptedPrivateKey,
		EnclaveEncryptedDataKey: dataKey,
		Nonce:                   nonce,
	}
	return material
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

func (s *Service) increment(name string, label string) {
	if s.prometheus == nil {
		return
	}
	s.prometheus.IncrementLabel(name, label)
}
