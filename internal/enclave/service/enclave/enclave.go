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
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/circlefin/arc-remote-signer/internal/common/crypto/aes"
	"github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	aesCommon "github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto/aes"
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
}

// New creates a new enclave service instance.
func New(nitroEnclaveEnabled bool, keystore keystore.Provider, enclavePvd enclave.Provider) *Service {
	return &Service{
		nitroEnclaveEnabled: nitroEnclaveEnabled,
		keystore:            keystore,
		enclavePvd:          enclavePvd,
	}
}

// GetAttestation returns the enclave attestation document.
func (s *Service) GetAttestation(_ context.Context, _ *pb.GetAttestationRequest) (*pb.GetAttestationResponse, error) {
	if s.enclavePvd == nil {
		return nil, status.Error(codes.FailedPrecondition, "enclave is not enabled")
	}
	return &pb.GetAttestationResponse{
		AttestationDocument: s.enclavePvd.AttestationDocument(),
	}, nil
}

// GenerateKey creates a new encrypted private key and returns its public key material.
func (s *Service) GenerateKey(_ context.Context, req *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is nil")
	}
	alg, err := toAlgorithm(req.Algorithm)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Get the plaintext data key from cache or decrypt it from enclave ciphertext.
	plainDataKey, err := s.loadDataKey(req.EnclaveEncryptedDataKey)
	if err != nil {
		return nil, err
	}

	// Generate a new signing key.
	secretKey, err := crypto.NewSecretKey(alg)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate secret key")
	}

	secretKeyBytes, err := secretKey.Serialize()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to serialize secret key")
	}

	// Derive the corresponding public key.
	publicKeyBytes, err := secretKey.PublicKey()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get public key")
	}

	// Encrypt private key bytes with AES-GCM using the plaintext data key.
	cipherData, nonce, err := aes.EncryptGCM(plainDataKey, secretKeyBytes)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encrypt secret key")
	}

	// Cache the key for future requests in this process.
	err = s.keystore.Set(buildCacheKey(cipherData, plainDataKey, nonce), secretKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to store secret key")
	}

	return &pb.GenerateKeyResponse{
		EncryptedPrivateKey: cipherData,
		Nonce:               nonce,
		PublicKey:           publicKeyBytes,
	}, nil
}

// GetPublicKey derives the public key from encrypted key material.
func (s *Service) GetPublicKey(ctx context.Context, req *pb.GetPublicKeyRequest) (*pb.GetPublicKeyResponse, error) {
	alg, err := toAlgorithm(req.Algorithm)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	secretKey, err := s.resolveSecretKey(ctx, alg, req.EncryptedKeyMaterial)
	if err != nil {
		return nil, err
	}

	publicKey, err := secretKey.PublicKey()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get public key")
	}

	return &pb.GetPublicKeyResponse{
		PublicKey: publicKey,
	}, nil
}

// SignMessage signs the request message with the decrypted secret key.
func (s *Service) SignMessage(ctx context.Context, req *pb.SignMessageRequest) (*pb.SignMessageResponse, error) {
	alg, err := toAlgorithm(req.Algorithm)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	secretKey, err := s.resolveSecretKey(ctx, alg, req.EncryptedKeyMaterial)
	if err != nil {
		return nil, err
	}

	// Sign with the resolved key.
	signature, err := secretKey.SignMessage(req.Message)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to sign message")
	}

	return &pb.SignMessageResponse{
		Signature: signature,
	}, nil
}

func (s *Service) resolveSecretKey(ctx context.Context, alg crypto.Algorithm, material *pb.EncryptedKeyMaterial) (crypto.Key, error) {
	if material == nil {
		return nil, status.Error(codes.InvalidArgument, "encrypted key material is nil")
	}

	plainDataKey, err := s.loadDataKey(material.EnclaveEncryptedDataKey)
	if err != nil {
		return nil, err
	}
	return s.loadSecretKey(ctx, alg, material.EncryptedPrivateKey, plainDataKey, material.Nonce)
}

func (s *Service) loadDataKey(enclaveEncryptedDataKey []byte) ([]byte, error) {
	// Return cached data key if available.
	if dataKey := s.keystore.Get(enclaveEncryptedDataKey); dataKey != nil {
		return dataKey.Serialize()
	}

	// In Nitro mode, decrypt the enclave-encrypted data key.
	plainDataKey := enclaveEncryptedDataKey
	if s.nitroEnclaveEnabled {
		if s.enclavePvd == nil {
			return nil, status.Error(codes.FailedPrecondition, "enclave provider is nil while nitro enclave is enabled")
		}
		var err error
		plainDataKey, err = s.enclavePvd.DecryptKMSEnvelopedKey(enclaveEncryptedDataKey)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to decrypt data key")
		}
	}

	// Validate and deserialize AES key bytes.
	dataKey, err := aesCommon.Deserialize(plainDataKey)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to deserialize data key")
	}

	// Cache deserialized key material.
	if err := s.keystore.Set(enclaveEncryptedDataKey, dataKey); err != nil {
		return nil, status.Error(codes.Internal, "failed to cache data key")
	}

	return dataKey.Serialize()
}

func (s *Service) loadSecretKey(_ context.Context, alg crypto.Algorithm, encryptedPrivateKey, dataKey, nonce []byte) (crypto.Key, error) {
	// Return cached decrypted secret key if available.
	cacheKey := buildCacheKey(encryptedPrivateKey, dataKey, nonce)
	if secretKey := s.keystore.Get(cacheKey); secretKey != nil {
		return secretKey, nil
	}

	// Decrypt private key bytes with AES-GCM.
	secretKeyPlaintext, err := aes.DecryptGCM(dataKey, encryptedPrivateKey, nonce)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to decrypt secret key")
	}

	// Deserialize private key according to the requested algorithm.
	secretKey, err := crypto.DeserializeSecretKey(alg, secretKeyPlaintext)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to deserialize secret key")
	}

	// Cache decrypted key for subsequent calls.
	err = s.keystore.Set(cacheKey, secretKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to cache secret key")
	}

	return secretKey, nil
}

// NOTE: The following helper functions (buildCacheKey, toAlgorithm) are duplicated from
// internal/enclave/service/key/key.go. This duplication is temporary - the old HTTP-based
// key service will be removed in a follow-up PR once this gRPC service is fully wired up.

// buildCacheKey builds a cache key from the given arguments.
// We use a composite key (encryptedPrivateKey + dataKey + nonce) instead of just encryptedPrivateKey
// to ensure the caller possesses both the encrypted private key AND the correct data key.
// This prevents unauthorized signing attempts with only a leaked encryptedPrivateKey.
func buildCacheKey(args ...[]byte) []byte {
	hash := sha256.New()
	lenBuf := make([]byte, 4)
	for _, arg := range args {
		binary.BigEndian.PutUint32(lenBuf, uint32(len(arg)))
		hash.Write(lenBuf)
		hash.Write(arg)
	}
	return hash.Sum(nil)
}

func toAlgorithm(algorithm pb.Algorithm) (crypto.Algorithm, error) {
	switch algorithm {
	case pb.Algorithm_ALGORITHM_BLS:
		return crypto.AlgorithmBLS, nil
	case pb.Algorithm_ALGORITHM_ED25519:
		return crypto.AlgorithmEd25519, nil
	default:
		return "", fmt.Errorf("invalid algorithm: %s", algorithm)
	}
}
