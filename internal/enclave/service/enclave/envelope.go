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
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awskms"
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

func fingerprintKeySource(req *pb.InitializeRequest) (keySourceFingerprint, error) {
	var parts [][]byte
	switch source := req.GetKeySource().(type) {
	case *pb.InitializeRequest_ExistingKey:
		env := source.ExistingKey
		if env == nil ||
			len(env.GetKmsEncryptedDataKey()) == 0 ||
			len(env.GetEncryptedPrivateKey()) == 0 ||
			len(env.GetNonce()) == 0 {
			return keySourceFingerprint{}, status.Error(codes.InvalidArgument, "existing_key is incomplete")
		}
		if _, err := toAlgorithm(env.GetAlgorithm()); err != nil {
			return keySourceFingerprint{}, status.Error(codes.InvalidArgument, err.Error())
		}
		parts = [][]byte{
			[]byte("initialize-existing-v1"),
			{byte(env.GetAlgorithm())},
			env.GetKmsEncryptedDataKey(),
			env.GetEncryptedPrivateKey(),
			env.GetNonce(),
		}
	case *pb.InitializeRequest_GenerateNew:
		if _, err := toAlgorithm(source.GenerateNew); err != nil {
			return keySourceFingerprint{}, status.Error(codes.InvalidArgument, err.Error())
		}
		algorithm := make([]byte, 4)
		binary.BigEndian.PutUint32(algorithm, uint32(source.GenerateNew))
		parts = [][]byte{[]byte("initialize-generate-v1"), algorithm}
	default:
		return keySourceFingerprint{}, status.Error(codes.InvalidArgument, "key_source is required")
	}

	var fingerprint keySourceFingerprint
	copy(fingerprint[:], hashKeySourceFields(parts...))
	return fingerprint, nil
}

func (s *Service) decryptDataKey(
	ctx context.Context,
	pvd awskms.Provider,
	kmsEncryptedDataKey []byte,
) ([]byte, error) {
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

func (s *Service) loadKeyCandidate(
	ctx context.Context,
	pvd awskms.Provider,
	env *pb.SecretEnvelope,
) (crypto.Key, error) {
	alg, err := toAlgorithm(env.GetAlgorithm())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	dataKey, err := s.decryptDataKey(ctx, pvd, env.GetKmsEncryptedDataKey())
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
	return secretKey, nil
}

func (s *Service) generateEnvelopeCandidate(
	ctx context.Context,
	pvd awskms.Provider,
	pbAlg pb.Algorithm,
) (*pb.SecretEnvelope, crypto.Key, []byte, error) {
	// Derive the crypto algorithm from the same proto value stamped into the
	// envelope, so the key-generation algorithm and the envelope's recorded
	// algorithm cannot drift.
	alg, err := toAlgorithm(pbAlg)
	if err != nil {
		return nil, nil, nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if pvd == nil {
		return nil, nil, nil, status.Error(codes.FailedPrecondition, "kms provider not initialized")
	}
	plainDataKey, kmsCipherDataKey, ciphertextForRecipient, err := pvd.GenerateDataKey(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("kms generate data key: %w", err)
	}
	if s.nitroEnclaveEnabled {
		if s.enclavePvd == nil {
			return nil, nil, nil, status.Error(codes.FailedPrecondition, "enclave provider is nil while nitro enclave is enabled")
		}
		plainDataKey, err = s.enclavePvd.DecryptKMSEnvelopedKey(ciphertextForRecipient)
		if err != nil {
			return nil, nil, nil, status.Error(codes.Internal, "key generation failed")
		}
	}
	dataKey, err := aesCommon.Deserialize(plainDataKey)
	if err != nil {
		return nil, nil, nil, status.Error(codes.Internal, "key generation failed")
	}
	dataKeyBytes, err := dataKey.Serialize()
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.Internal, "serialize data key: %v", err)
	}
	secretKey, err := crypto.NewSecretKey(alg)
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.Internal, "generate secret key: %v", err)
	}
	secretKeyBytes, err := secretKey.Serialize()
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.Internal, "serialize secret key: %v", err)
	}
	publicKey, err := secretKey.PublicKey()
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.Internal, "get public key: %v", err)
	}
	cipher, nonce, err := aes.EncryptGCM(dataKeyBytes, secretKeyBytes)
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.Internal, "encrypt secret key: %v", err)
	}
	env := &pb.SecretEnvelope{
		Algorithm:           pbAlg,
		KmsEncryptedDataKey: kmsCipherDataKey,
		EncryptedPrivateKey: cipher,
		Nonce:               nonce,
	}
	return env, secretKey, publicKey, nil
}

// hashKeySourceFields hashes length-prefixed fields for a fingerprint.
func hashKeySourceFields(args ...[]byte) []byte {
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
