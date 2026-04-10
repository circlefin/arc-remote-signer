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

// Package aes provides an AES key implementation.
package aes

import (
	"fmt"

	"github.com/circlefin/arc-remote-signer/internal/common/crypto/rand"
)

// Key ...
type Key struct {
	secretKey []byte
}

// New creates a new AES key.
func New() (*Key, error) {
	plainDataKey, err := rand.GenerateRandomBytes(32)
	if err != nil {
		return nil, err
	}
	return &Key{
		secretKey: plainDataKey,
	}, nil
}

// PublicKey returns the error because AES does not have a public key.
func (k *Key) PublicKey() ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// SignMessage returns the error because AES does not have to sign messages.
func (k *Key) SignMessage(_ []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// Serialize serializes the AES key.
func (k *Key) Serialize() ([]byte, error) {
	return k.secretKey, nil
}

// Deserialize deserializes the AES key.
func Deserialize(data []byte) (*Key, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", 32, len(data))
	}
	return &Key{
		secretKey: data,
	}, nil
}
