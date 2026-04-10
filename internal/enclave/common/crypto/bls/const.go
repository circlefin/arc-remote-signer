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

// BLS cryptographic element sizes in bytes.
const (
	// IKMSize is the size of the Input Key Material used for BLS key generation.
	IKMSize = 32
	// PublicKeySize is the size of a serialized BLS public key in bytes.
	PublicKeySize = 96
	// SignatureSize is the size of a serialized BLS signature in bytes.
	SignatureSize = 192
	// SecretKeySize is the size of a serialized BLS secret key in bytes.
	SecretKeySize = 32
)

// Domain separation tags for BLS signatures.
// Refer to BLS Signatures IETF standard for more details: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2
// Reference implementation: https://github.com/ava-labs/avalanchego/blob/master/utils/crypto/bls/ciphersuite.go#L13-L16
var (
	// DSTSignature is the domain separation tag for minimal-signature-size BLS signatures.
	DSTSignature = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
)
