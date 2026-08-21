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
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/circlefin/arc-remote-signer/internal/common/crypto/aes"
	"github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	aesCommon "github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto/aes"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// kmsStatusError maps a raw KMS or enclave SDK error from the envelope read/generate
// path to a gRPC status, prefixed with the call site (e.g. "kms decrypt data
// key") for context. It delegates to toStatusError so this path surfaces the
// same context-cancel/deadline and awskms.StatusFromError mapping as the
// Initialize path (runInitStatusError).
func kmsStatusError(prefix string, err error) error {
	return toStatusError(prefix, err)
}

// loadKeyFromEnvelope and generateEnvelope are the sole decrypt→deserialize→
// cache and mint→wrap implementations for the enclave. The legacy
// EncryptedKeyMaterial path they once mirrored was removed in T3 (CCHAIN-2170).

// envelopeCacheKey derives the keystore key for a SecretEnvelope directly
// from its ciphertext fields, so a warm cache hit needs no KMS or RSA work.
func envelopeCacheKey(env *pb.SecretEnvelope) []byte {
	alg := []byte{byte(env.GetAlgorithm())}
	return buildCacheKey(alg, env.GetKmsEncryptedDataKey(), env.GetEncryptedPrivateKey(), env.GetNonce())
}

// decryptDataKeyFromKMS recovers the plaintext AES data key from its KMS
// ciphertext entirely inside the enclave. In Nitro mode the enclave passes
// its NSM-signed attestation document to KMS (RecipientInfo), so KMS returns
// the data key encrypted to the attested RSA public key
// (CiphertextForRecipient). The enclave process decrypts it with the
// corresponding in-memory RSA private key, so the plaintext never leaves the
// enclave even though awsproxy relays the bytes. In dev/CI (no attestation)
// KMS returns the plaintext data key directly.
func (s *Service) decryptDataKeyFromKMS(ctx context.Context, kmsEncryptedDataKey []byte) ([]byte, error) {
	pvd := s.kmsProvider()
	if pvd == nil {
		return nil, status.Error(codes.FailedPrecondition, "kms provider not initialized")
	}
	plaintext, ciphertextForRecipient, err := pvd.Decrypt(ctx, kmsEncryptedDataKey)
	if err != nil {
		return nil, kmsStatusError("kms decrypt data key", err)
	}
	if s.nitroEnclaveEnabled {
		if s.enclavePvd == nil {
			return nil, status.Error(codes.FailedPrecondition, "enclave provider is nil while nitro enclave is enabled")
		}
		plaintext, err = s.enclavePvd.DecryptKMSEnvelopedKey(ciphertextForRecipient)
		if err != nil {
			return nil, status.Error(codes.Internal, "key recovery failed")
		}
	}
	// Deserialize->Serialize round-trips the KMS/enclave-produced key bytes through
	// the aes type to validate and canonicalize them before downstream AES-GCM
	// use, so a malformed data key fails here with a clear error rather than
	// deeper in DecryptGCM. The bytes are KMS/enclave output (not raw client input),
	// so a failure is Internal — matching generateEnvelope's identical step.
	dataKey, err := aesCommon.Deserialize(plaintext)
	if err != nil {
		return nil, status.Error(codes.Internal, "key recovery failed")
	}
	return dataKey.Serialize()
}

// loadKeyFromEnvelope returns the crypto.Key for env, hitting the keystore
// cache first and otherwise KMS-decrypting the data key, AES-decrypting the
// private key, deserializing, and caching under envelopeCacheKey(env).
//
// The algorithm is taken from the envelope itself (not the request), so it is
// the single source of truth for both the cache key and deserialization. This
// avoids a warm-cache/cold-cache divergence where a request algorithm that
// disagrees with the envelope would be silently honored on a hit but rejected
// on a miss.
func (s *Service) loadKeyFromEnvelope(ctx context.Context, env *pb.SecretEnvelope) (crypto.Key, error) {
	alg, err := toAlgorithm(env.GetAlgorithm())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	cacheKey := envelopeCacheKey(env)
	if k := s.keystore.Get(cacheKey); k != nil {
		return k, nil
	}
	dataKey, err := s.decryptDataKeyFromKMS(ctx, env.GetKmsEncryptedDataKey())
	if err != nil {
		return nil, err
	}
	secretKeyPlaintext, err := aes.DecryptGCM(dataKey, env.GetEncryptedPrivateKey(), env.GetNonce())
	if err != nil {
		return nil, status.Error(codes.Internal, "key recovery failed")
	}
	secretKey, err := crypto.DeserializeSecretKey(alg, secretKeyPlaintext)
	if err != nil {
		return nil, status.Error(codes.Internal, "key recovery failed")
	}
	if err := s.keystore.Set(cacheKey, secretKey); err != nil {
		return nil, status.Errorf(codes.Internal, "cache secret key: %v", err)
	}
	return secretKey, nil
}

// generateEnvelope mints a fresh data key in-enclave (GenerateDataKey followed
// by in-process RSA decryption of CiphertextForRecipient in Nitro), generates a
// signing key, AES-GCM-wraps it under the data key, caches it under the envelope
// cache key, and returns the SecretEnvelope plus the public key.
func (s *Service) generateEnvelope(ctx context.Context, pbAlg pb.Algorithm) (*pb.SecretEnvelope, []byte, error) {
	// Derive the crypto algorithm from the same proto value stamped into the
	// envelope, so the key-generation algorithm and the envelope's recorded
	// algorithm cannot drift.
	alg, err := toAlgorithm(pbAlg)
	if err != nil {
		return nil, nil, status.Error(codes.InvalidArgument, err.Error())
	}
	pvd := s.kmsProvider()
	if pvd == nil {
		return nil, nil, status.Error(codes.FailedPrecondition, "kms provider not initialized")
	}
	plainDataKey, kmsCipherDataKey, ciphertextForRecipient, err := pvd.GenerateDataKey(ctx)
	if err != nil {
		return nil, nil, kmsStatusError("kms generate data key", err)
	}
	if s.nitroEnclaveEnabled {
		if s.enclavePvd == nil {
			return nil, nil, status.Error(codes.FailedPrecondition, "enclave provider is nil while nitro enclave is enabled")
		}
		plainDataKey, err = s.enclavePvd.DecryptKMSEnvelopedKey(ciphertextForRecipient)
		if err != nil {
			return nil, nil, status.Error(codes.Internal, "key generation failed")
		}
	}
	dataKey, err := aesCommon.Deserialize(plainDataKey)
	if err != nil {
		return nil, nil, status.Error(codes.Internal, "key generation failed")
	}
	dataKeyBytes, err := dataKey.Serialize()
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "serialize data key: %v", err)
	}
	secretKey, err := crypto.NewSecretKey(alg)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "generate secret key: %v", err)
	}
	secretKeyBytes, err := secretKey.Serialize()
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "serialize secret key: %v", err)
	}
	publicKey, err := secretKey.PublicKey()
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "get public key: %v", err)
	}
	cipher, nonce, err := aes.EncryptGCM(dataKeyBytes, secretKeyBytes)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "encrypt secret key: %v", err)
	}
	env := &pb.SecretEnvelope{
		Algorithm:           pbAlg,
		KmsEncryptedDataKey: kmsCipherDataKey,
		EncryptedPrivateKey: cipher,
		Nonce:               nonce,
	}
	if err := s.keystore.Set(envelopeCacheKey(env), secretKey); err != nil {
		return nil, nil, status.Errorf(codes.Internal, "cache secret key: %v", err)
	}
	return env, publicKey, nil
}

// buildCacheKey builds a keystore cache key from the given arguments.
// We use a composite key (algorithm + ciphertext fields) instead of a single
// field to ensure the caller possesses the full envelope, not just one leaked
// component.
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

// toAlgorithm maps a proto Algorithm to the enclave crypto algorithm.
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
