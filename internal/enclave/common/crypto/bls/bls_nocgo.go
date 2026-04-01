//go:build !cgo

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

package bls

import "fmt"

// ErrCGODisabled indicates BLS operations are unavailable without CGO.
var ErrCGODisabled = fmt.Errorf("bls requires cgo; rebuild with CGO_ENABLED=1")

// Key represents a BLS key.
type Key struct{}

// New creates a new BLS key.
func New() (*Key, error) {
	return nil, ErrCGODisabled
}

// PublicKey returns the public key.
func (k *Key) PublicKey() ([]byte, error) {
	return nil, ErrCGODisabled
}

// SignMessage signs a message.
func (k *Key) SignMessage(message []byte) ([]byte, error) {
	return nil, ErrCGODisabled
}

// Serialize serializes the BLS key.
func (k *Key) Serialize() ([]byte, error) {
	return nil, ErrCGODisabled
}

// Deserialize deserializes a BLS key.
func Deserialize(data []byte) (*Key, error) {
	return nil, ErrCGODisabled
}

// VerifySignedMessage verifies a signed message with the given public key.
func VerifySignedMessage(signedMessage []byte, message []byte, publicKey []byte) (bool, error) {
	return false, ErrCGODisabled
}
