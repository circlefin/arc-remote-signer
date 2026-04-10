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

//go:generate mockgen -source=enclave.go -destination=enclave_mock.go -package=enclave .

// Package enclave is a package for the enclave.
package enclave

import (
	enclave "github.com/edgebitio/nitro-enclaves-sdk-go"
)

var _ Provider = (*provider)(nil)

// Provider is the interface for the enclave provider.
type Provider interface {
	DecryptKMSEnvelopedKey(ciphertext []byte) (plainText []byte, err error)
	AttestationDocument() []byte
}

// provider is the implementation of the Provider interface.
type provider struct {
	enclaveHandle       *enclave.EnclaveHandle
	attestationDocument []byte
}

// New creates a new provider.
func New() (Provider, error) {
	handler, err := enclave.GetOrInitializeHandle()
	if err != nil {
		return nil, err
	}
	attestationDocument, err := handler.Attest(enclave.AttestationOptions{})
	if err != nil {
		return nil, err
	}
	return &provider{
		enclaveHandle:       handler,
		attestationDocument: attestationDocument,
	}, nil
}

// DecryptKMSEnvelopedKey decrypts the given ciphertext using the Nitro enclave.
func (n *provider) DecryptKMSEnvelopedKey(ciphertext []byte) (plainText []byte, err error) {
	plainText, err = n.enclaveHandle.DecryptKMSEnvelopedKey(ciphertext)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

// AttestationDocument returns the attestation document.
func (n *provider) AttestationDocument() []byte {
	return n.attestationDocument
}
