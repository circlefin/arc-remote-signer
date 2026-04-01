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

package signer

import (
	"sync"
	"testing"

	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testEncryptedPrivateKey = "test-encrypted-private-key"
	testPlainDataKey        = "test-plain-data-key"
	testNonce               = "test-nonce"
	testPublicKey           = "test-public-key"
)

func TestCache_SetAndGet(t *testing.T) {
	c := newCache()

	require.Nil(t, c.get())

	testKey := &key{
		encryptedKeyMaterial: &pb.EncryptedKeyMaterial{
			EncryptedPrivateKey:     []byte(testEncryptedPrivateKey),
			EnclaveEncryptedDataKey: []byte(testPlainDataKey),
			Nonce:                   []byte(testNonce),
		},
		publicKey: []byte(testPublicKey),
	}

	c.set(testKey)

	got := c.get()
	require.NotNil(t, got)
	assertKeyEqual(t, got, testKey)
}

func TestCache_UpdateKey(t *testing.T) {
	c := newCache()

	initialKey := &key{
		encryptedKeyMaterial: &pb.EncryptedKeyMaterial{
			EncryptedPrivateKey:     []byte(testEncryptedPrivateKey),
			EnclaveEncryptedDataKey: []byte(testPlainDataKey),
			Nonce:                   []byte(testNonce),
		},
		publicKey: []byte(testPublicKey),
	}
	c.set(initialKey)

	got := c.get()
	assertKeyEqual(t, got, initialKey)

	updatedKey := &key{
		encryptedKeyMaterial: &pb.EncryptedKeyMaterial{
			EncryptedPrivateKey:     []byte("updated-encrypted-private-key"),
			EnclaveEncryptedDataKey: []byte("updated-plain-data-key"),
			Nonce:                   []byte("updated-nonce"),
		},
		publicKey: []byte("updated-public-key"),
	}
	c.set(updatedKey)

	got = c.get()
	assertKeyEqual(t, got, updatedKey)
}

func TestCache_ConcurrentAccess(_ *testing.T) {
	c := newCache()
	testKey := &key{
		encryptedKeyMaterial: &pb.EncryptedKeyMaterial{
			EncryptedPrivateKey:     []byte(testEncryptedPrivateKey),
			EnclaveEncryptedDataKey: []byte(testPlainDataKey),
			Nonce:                   []byte(testNonce),
		},
		publicKey: []byte(testPublicKey),
	}
	var wg sync.WaitGroup

	// Writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			c.set(testKey)
		}
	}()

	// Reader goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = c.get()
		}
	}()

	wg.Wait()
}

func TestCache_MultipleReaders(t *testing.T) {
	c := newCache()
	testKey := &key{
		encryptedKeyMaterial: &pb.EncryptedKeyMaterial{
			EncryptedPrivateKey:     []byte(testEncryptedPrivateKey),
			EnclaveEncryptedDataKey: []byte(testPlainDataKey),
			Nonce:                   []byte(testNonce),
		},
		publicKey: []byte(testPublicKey),
	}

	c.set(testKey)

	var wg sync.WaitGroup
	readerCount := 10

	for i := 0; i < readerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				got := c.get()
				if assert.NotNil(t, got) {
					assertKeyEqual(t, got, testKey)
				}
			}
		}()
	}

	wg.Wait()
}

func assertKeyEqual(t *testing.T, got, want *key) {
	t.Helper()
	assert.NotNil(t, got)
	assert.NotNil(t, got.encryptedKeyMaterial)
	assert.NotNil(t, want.encryptedKeyMaterial)
	assert.Equal(t, want.encryptedKeyMaterial.EncryptedPrivateKey, got.encryptedKeyMaterial.EncryptedPrivateKey)
	assert.Equal(t, want.encryptedKeyMaterial.EnclaveEncryptedDataKey, got.encryptedKeyMaterial.EnclaveEncryptedDataKey)
	assert.Equal(t, want.encryptedKeyMaterial.Nonce, got.encryptedKeyMaterial.Nonce)
	assert.Equal(t, want.publicKey, got.publicKey)
}

func TestCache_NewCache(t *testing.T) {
	c := newCache()

	require.NotNil(t, c)
	require.Nil(t, c.get())
}
