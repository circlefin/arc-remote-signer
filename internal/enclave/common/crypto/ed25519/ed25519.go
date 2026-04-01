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

// Package ed25519 provides an Ed25519 key implementation.
package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// Key represents an Ed25519 key.
type Key struct {
	privateKey ed25519.PrivateKey
}

// New creates a new Ed25519 key.
func New() (*Key, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	// Verify the key was generated correctly
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privateKey))
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(publicKey))
	}

	return &Key{
		privateKey: privateKey,
	}, nil
}

// PublicKey returns the public key.
func (k *Key) PublicKey() ([]byte, error) {
	// Ed25519 private key contains the public key in the last 32 bytes
	publicKey := k.privateKey.Public().(ed25519.PublicKey)
	return publicKey, nil
}

// SignMessage signs a message.
func (k *Key) SignMessage(message []byte) ([]byte, error) {
	signature := ed25519.Sign(k.privateKey, message)
	return signature, nil
}

// Serialize serializes the Ed25519 key.
func (k *Key) Serialize() ([]byte, error) {
	// Return a copy of the private key
	serialized := make([]byte, len(k.privateKey))
	copy(serialized, k.privateKey)
	return serialized, nil
}

// Deserialize deserializes an Ed25519 key.
func Deserialize(data []byte) (*Key, error) {
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", ed25519.PrivateKeySize, len(data))
	}

	privateKey := ed25519.PrivateKey(data)

	// Verify the key is valid by checking if we can derive the public key
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("failed to derive valid public key")
	}

	return &Key{
		privateKey: privateKey,
	}, nil
}

// VerifySignedMessage verifies a signed message with the given public key.
func VerifySignedMessage(signature []byte, message []byte, publicKey []byte) (bool, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(publicKey))
	}
	if len(signature) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature size: expected %d, got %d", ed25519.SignatureSize, len(signature))
	}

	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature), nil
}
