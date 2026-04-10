//go:build cgo

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

// Package bls provides a BLS key implementation.
package bls

import (
	"crypto/rand"
	"fmt"

	blst "github.com/supranational/blst/bindings/go"
)

// Key represents a BLS key.
type Key struct {
	secretKey *blst.SecretKey
}

// New creates a new BLS key.
func New() (*Key, error) {
	var ikm [IKMSize]byte
	_, err := rand.Read(ikm[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	sk := blst.KeyGen(ikm[:])
	defer func() {
		// Zero out the IKM after use to avoid leaving sensitive data in memory.
		for i := range ikm {
			ikm[i] = 0
		}
	}()

	return &Key{
		secretKey: sk,
	}, nil
}

// PublicKey returns the public key.
func (k *Key) PublicKey() ([]byte, error) {
	return new(blst.P1Affine).From(k.secretKey).Serialize(), nil
}

// SignMessage signs a message.
func (k *Key) SignMessage(message []byte) ([]byte, error) {
	return new(blst.P2Affine).Sign(k.secretKey, message, DSTSignature).Serialize(), nil
}

// Serialize serializes the BLS key.
func (k *Key) Serialize() ([]byte, error) {
	return k.secretKey.Serialize(), nil
}

// Deserialize deserializes a BLS key.
func Deserialize(data []byte) (*Key, error) {
	sk := new(blst.SecretKey).Deserialize(data)
	if sk == nil {
		return nil, fmt.Errorf("failed to deserialize secret key")
	}
	return &Key{
		secretKey: sk,
	}, nil
}

// VerifySignedMessage verifies a signed message with the given public key.
func VerifySignedMessage(signedMessage []byte, message []byte, publicKey []byte) (bool, error) {
	return verify(signedMessage, message, publicKey, DSTSignature)
}

func verify(signature []byte, message []byte, publicKey []byte, dst []byte) (bool, error) {
	pk := new(blst.P1Affine).Deserialize(publicKey)
	if pk == nil {
		return false, fmt.Errorf("failed to deserialize public key")
	}

	sig := new(blst.P2Affine).Deserialize(signature)
	if sig == nil {
		return false, fmt.Errorf("failed to deserialize signature")
	}

	return sig.Verify(true, pk, false, message, dst), nil
}
