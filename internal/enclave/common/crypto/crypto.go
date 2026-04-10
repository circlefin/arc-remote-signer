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

// Package crypto provides a common interface for cryptographic operations.
package crypto

import (
	"fmt"

	commonCrypto "github.com/circlefin/arc-remote-signer/internal/common/crypto"
	"github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto/bls"
	"github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto/ed25519"
)

// Algorithm is an alias for the common Algorithm type.
type Algorithm = commonCrypto.Algorithm

const (
	// AlgorithmBLS is the BLS algorithm.
	AlgorithmBLS = commonCrypto.AlgorithmBLS
	// AlgorithmEd25519 is the Ed25519 algorithm.
	AlgorithmEd25519 = commonCrypto.AlgorithmEd25519
)

var (
	// ErrInvalidAlgorithm is the error for invalid algorithm.
	ErrInvalidAlgorithm = fmt.Errorf("invalid algorithm")
)

// Key is a secret key interface.
type Key interface {
	PublicKey() ([]byte, error)
	SignMessage(message []byte) ([]byte, error)
	Serialize() ([]byte, error)
}

// NewSecretKey creates a new secret key with the given algorithm.
func NewSecretKey(alg Algorithm) (Key, error) {
	switch alg {
	case AlgorithmBLS:
		return bls.New()
	case AlgorithmEd25519:
		return ed25519.New()
	default:
		return nil, ErrInvalidAlgorithm
	}
}

// DeserializeSecretKey deserializes a secret key with the given algorithm.
func DeserializeSecretKey(alg Algorithm, secretKey []byte) (Key, error) {
	switch alg {
	case AlgorithmBLS:
		return bls.Deserialize(secretKey)
	case AlgorithmEd25519:
		return ed25519.Deserialize(secretKey)
	default:
		return nil, ErrInvalidAlgorithm
	}
}

// VerifySignedMessage verifies a signed message with the given algorithm and public key.
func VerifySignedMessage(alg Algorithm, signature []byte, message []byte, publicKey []byte) (bool, error) {
	switch alg {
	case AlgorithmBLS:
		return bls.VerifySignedMessage(signature, message, publicKey)
	case AlgorithmEd25519:
		return ed25519.VerifySignedMessage(signature, message, publicKey)
	default:
		return false, ErrInvalidAlgorithm
	}
}
