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
	"bytes"
	"encoding/gob"
)

// header represents the AES encrypted data.
// It contains the cipher key, cipher data, and nonce.
type header struct {
	CipherKey  []byte
	CipherData []byte
	Nonce      []byte
}

// MarshalBinary marshals the header to binary format.
func (h *header) MarshalBinary() ([]byte, error) {
	type headerAlias header
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode((*headerAlias)(h)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary unmarshals the header from binary format.
func (h *header) UnmarshalBinary(data []byte) error {
	type headerAlias header
	return gob.NewDecoder(bytes.NewReader(data)).Decode((*headerAlias)(h))
}
