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

// Package aes provides helpers for AES-GCM encryption and decryption.
package aes

import (
	cryptoaes "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

var (
	// ErrInvalidNonceLength is returned when nonce length does not match AES-GCM nonce size.
	ErrInvalidNonceLength = errors.New("invalid nonce length")
)

// EncryptGCM encrypts plaintext with AES-GCM using the given key.
// AES key length must be 16, 24, or 32 bytes.
func EncryptGCM(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := cryptoaes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// DecryptGCM decrypts ciphertext with AES-GCM using the given key and nonce.
// AES key length must be 16, 24, or 32 bytes.
func DecryptGCM(key, ciphertext, nonce []byte) (plaintext []byte, err error) {
	block, err := cryptoaes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aesgcm.NonceSize() {
		return nil, ErrInvalidNonceLength
	}

	plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
