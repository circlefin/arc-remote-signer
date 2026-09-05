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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/enclave/kmsrecipient"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

const rsaKeyBits = 2048

var _ Provider = (*provider)(nil)

// Provider is the interface for the enclave provider.
type Provider interface {
	DecryptKMSEnvelopedKey(ciphertext []byte) (plainText []byte, err error)
	AttestKMSRecipient() ([]byte, error)
	Attest(userData []byte) ([]byte, error)
}

type nsmSession interface {
	Send(request.Request) (response.Response, error)
	Close() error
}

type nsmSessionFactory func() (nsmSession, error)

// provider is the implementation of the Provider interface.
type provider struct {
	privateKey  *rsa.PrivateKey
	publicKey   []byte
	openSession nsmSessionFactory
}

// New creates a new provider.
func New() (Provider, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate attestation key: %w", err)
	}
	return newProvider(openDefaultSession, privateKey)
}

func openDefaultSession() (nsmSession, error) {
	return nsm.OpenDefaultSession()
}

func newProvider(openSession nsmSessionFactory, privateKey *rsa.PrivateKey) (*provider, error) {
	if privateKey == nil {
		return nil, errors.New("attestation private key is nil")
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal attestation public key: %w", err)
	}
	return &provider{
		privateKey:  privateKey,
		publicKey:   publicKey,
		openSession: openSession,
	}, nil
}

func requestAttestation(openSession nsmSessionFactory, req *request.Attestation) ([]byte, error) {
	session, err := openSession()
	if err != nil {
		return nil, fmt.Errorf("open NSM session: %w", err)
	}
	defer func() { _ = session.Close() }()

	result, err := session.Send(req)
	if err != nil {
		return nil, fmt.Errorf("request NSM attestation: %w", err)
	}
	if result.Error != "" {
		return nil, fmt.Errorf("request NSM attestation: %s", result.Error)
	}
	if result.Attestation == nil || len(result.Attestation.Document) == 0 {
		return nil, errors.New("NSM response missing attestation document")
	}

	return bytes.Clone(result.Attestation.Document), nil
}

// DecryptKMSEnvelopedKey decrypts CiphertextForRecipient with the in-memory RSA
// private key whose public key is included in the NSM-signed attestation.
func (n *provider) DecryptKMSEnvelopedKey(ciphertext []byte) (plainText []byte, err error) {
	return kmsrecipient.Decrypt(n.privateKey, ciphertext)
}

// AttestKMSRecipient requests a new document for the RSA public key that the
// enclave retains. KMS uses this document to encrypt a data key for the enclave.
func (n *provider) AttestKMSRecipient() ([]byte, error) {
	return requestAttestation(n.openSession, &request.Attestation{PublicKey: bytes.Clone(n.publicKey)})
}

// Attest opens an NSM session. Attest requests a new document. Attest closes the
// session before it returns. The signed user_data field contains the supplied
// bytes.
func (n *provider) Attest(userData []byte) ([]byte, error) {
	return requestAttestation(n.openSession, &request.Attestation{UserData: bytes.Clone(userData)})
}
