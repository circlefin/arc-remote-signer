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

// Package rand provides helpers for generating cryptographically secure random bytes.
package rand

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"math/big"
)

const (
	saltSize          = 32
	randStringCharset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// GenerateFixedSizeRandomBytes returns a fixed-size random byte slice.
func GenerateFixedSizeRandomBytes() ([]byte, error) {
	return GenerateRandomBytes(saltSize)
}

// GenerateRandomBytes returns n random bytes using crypto/rand.
func GenerateRandomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("invalid length: %d", n)
	}
	mainBuff := make([]byte, n)
	if _, err := io.ReadFull(crand.Reader, mainBuff); err != nil {
		return nil, fmt.Errorf("reading from crypto/rand failed: %w", err)
	}
	return mainBuff, nil
}

// MustGenerateFixedSizeRandomBytes returns a fixed-size random byte slice and panics on failure.
func MustGenerateFixedSizeRandomBytes() []byte {
	b, err := GenerateFixedSizeRandomBytes()
	if err != nil {
		panic(err)
	}
	return b
}

// MustGenerateRandomBytes returns n random bytes and panics on failure.
func MustGenerateRandomBytes(n int) []byte {
	b, err := GenerateRandomBytes(n)
	if err != nil {
		panic(err)
	}
	return b
}

// GenerateRandomString generates a cryptographically secure random string of specified length.
// It uses crypto/rand instead of math/rand for better randomness.
func GenerateRandomString(length int) (string, error) {
	if length < 0 {
		return "", fmt.Errorf("invalid length: %d", length)
	}
	if length == 0 {
		return "", nil
	}

	b := make([]byte, length)
	charsetLen := big.NewInt(int64(len(randStringCharset)))

	for i := range b {
		// Generate cryptographically secure random index
		randomIndex, err := crand.Int(crand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate random string: %w", err)
		}
		b[i] = randStringCharset[randomIndex.Int64()]
	}

	return string(b), nil
}

// MustGenerateRandomString generates a cryptographically secure random string and panics on failure.
func MustGenerateRandomString(length int) string {
	s, err := GenerateRandomString(length)
	if err != nil {
		panic(err)
	}
	return s
}
