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

//go:generate mockgen -source $GOFILE -destination keystore_mock.go -package $GOPACKAGE keystore

// Package keystore provides a keystore provider.
package keystore

import (
	"encoding/hex"
	"sync"

	"github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
)

var _ Provider = (*ProviderImpl)(nil)

// Provider is the interface for the keystore provider.
type Provider interface {
	Set(ciphertext []byte, secretKey crypto.Key) error
	Get(ciphertext []byte) (secretKey crypto.Key)
}

// ProviderImpl is the implementation of the keystore provider.
type ProviderImpl struct {
	mu    sync.RWMutex
	store map[string]crypto.Key
}

// New returns a new keystore provider.
func New() *ProviderImpl {
	return &ProviderImpl{
		store: make(map[string]crypto.Key),
	}
}

// Set sets the secret key.
func (p *ProviderImpl) Set(ciphertext []byte, secretKey crypto.Key) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.store[hex.EncodeToString(ciphertext)] = secretKey
	return nil
}

// Get gets the secret key. Returns nil if the secret key is not found.
func (p *ProviderImpl) Get(ciphertext []byte) crypto.Key {
	p.mu.RLock()
	defer p.mu.RUnlock()
	secretKey, ok := p.store[hex.EncodeToString(ciphertext)]
	if !ok {
		return nil
	}
	return secretKey
}
