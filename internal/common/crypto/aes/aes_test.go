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

package aes

import (
	cryptoaes "crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func generateKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := crand.Read(key)
	require.NoError(t, err, "failed to generate random key")
	return key
}

func gcmNonceSizeForKey(t *testing.T, key []byte) int {
	t.Helper()
	block, err := cryptoaes.NewCipher(key)
	require.NoError(t, err, "failed to build cipher for nonce-size check")
	aesgcm, err := cipher.NewGCM(block)
	require.NoError(t, err, "failed to build GCM for nonce-size check")
	return aesgcm.NonceSize()
}

func TestEncryptGCM_RoundTrip(t *testing.T) {
	key := generateKey(t)
	nonceSize := gcmNonceSizeForKey(t, key)
	plaintext := []byte("test-message")

	ciphertext, nonce, err := EncryptGCM(key, plaintext)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)
	require.Len(t, nonce, nonceSize)

	decrypted, err := DecryptGCM(key, ciphertext, nonce)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestEncryptGCM_InvalidKey(t *testing.T) {
	_, _, err := EncryptGCM(nil, []byte("plaintext"))
	require.ErrorAs(t, err, new(cryptoaes.KeySizeError))
}

func TestDecryptGCM_InvalidParameters(t *testing.T) {
	t.Run("nil key returns key size error", func(t *testing.T) {
		_, err := DecryptGCM(nil, nil, nil)
		require.ErrorAs(t, err, new(cryptoaes.KeySizeError))
	})

	t.Run("nil nonce returns invalid nonce length error", func(t *testing.T) {
		key := generateKey(t)
		_, err := DecryptGCM(key, []byte("cipher"), nil)
		require.ErrorIs(t, err, ErrInvalidNonceLength)
	})

	t.Run("short nonce returns invalid nonce length error", func(t *testing.T) {
		key := generateKey(t)
		ciphertext, nonce, err := EncryptGCM(key, []byte("nonce-size-check"))
		require.NoError(t, err)

		_, err = DecryptGCM(key, ciphertext, nonce[:len(nonce)-1])
		require.ErrorIs(t, err, ErrInvalidNonceLength)
	})

	t.Run("long nonce returns invalid nonce length error", func(t *testing.T) {
		key := generateKey(t)
		ciphertext, nonce, err := EncryptGCM(key, []byte("nonce-size-check"))
		require.NoError(t, err)

		longNonce := append([]byte{}, nonce...)
		longNonce = append(longNonce, byte(0))
		_, err = DecryptGCM(key, ciphertext, longNonce)
		require.ErrorIs(t, err, ErrInvalidNonceLength)
	})
}

func TestDecryptGCM_TamperedInputs(t *testing.T) {
	key := generateKey(t)
	plaintext := []byte("tamper-check")

	ciphertext, nonce, err := EncryptGCM(key, plaintext)
	require.NoError(t, err)

	t.Run("modified ciphertext", func(t *testing.T) {
		tamperedCiphertext := append([]byte{}, ciphertext...)
		tamperedCiphertext[0] ^= 0x01

		_, err := DecryptGCM(key, tamperedCiphertext, nonce)
		require.Error(t, err)
	})

	t.Run("wrong key", func(t *testing.T) {
		wrongKey := generateKey(t)

		_, err := DecryptGCM(wrongKey, ciphertext, nonce)
		require.Error(t, err)
	})

	t.Run("wrong nonce", func(t *testing.T) {
		wrongNonce := append([]byte{}, nonce...)
		wrongNonce[0] ^= 0x01

		_, err := DecryptGCM(key, ciphertext, wrongNonce)
		require.Error(t, err)
	})
}
