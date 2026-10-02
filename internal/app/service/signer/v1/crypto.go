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

package v1

import (
	"bytes"
	"encoding/gob"

	"github.com/circlefin/arc-remote-signer/proto/pb"
)

// header represents the AES encrypted data.
// It contains the algorithm, cipher key, cipher data, and nonce.
//
// The stored-secret format is preserved across the KMS-in-enclave migration:
// CipherKey/CipherData/Nonce map 1:1 onto the SecretEnvelope's
// kms_encrypted_data_key/encrypted_private_key/nonce, so existing validator
// secrets load without re-registration.
//
// Algorithm records the algorithm the key was generated under so a later reload
// can fail cleanly on a config mismatch instead of silently signing under the
// wrong one. It is gob-backward-compatible: secrets written before this field
// decode as ALGORITHM_UNSPECIFIED.
type header struct {
	Algorithm  pb.Algorithm
	CipherKey  []byte
	CipherData []byte
	Nonce      []byte
}

// toSecretEnvelope maps a stored header to the proto SecretEnvelope the
// enclave decrypts in-enclave.
func (h *header) toSecretEnvelope(alg pb.Algorithm) *pb.SecretEnvelope {
	return &pb.SecretEnvelope{
		Algorithm:           alg,
		KmsEncryptedDataKey: h.CipherKey,
		EncryptedPrivateKey: h.CipherData,
		Nonce:               h.Nonce,
	}
}

// headerFromSecretEnvelope maps an enclave-produced SecretEnvelope back to
// the stored header format for persistence in Secrets Manager.
func headerFromSecretEnvelope(env *pb.SecretEnvelope) *header {
	return &header{
		Algorithm:  env.GetAlgorithm(),
		CipherKey:  env.GetKmsEncryptedDataKey(),
		CipherData: env.GetEncryptedPrivateKey(),
		Nonce:      env.GetNonce(),
	}
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
