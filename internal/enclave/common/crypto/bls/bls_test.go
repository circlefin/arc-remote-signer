//go:build cgo

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

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/suite"
)

type blsTestSuite struct {
	suite.Suite
	BLSKey *Key
}

func (s *blsTestSuite) SetupTest() {
	blsKey, err := New()
	s.Require().NoError(err)
	s.BLSKey = blsKey
}

func (s *blsTestSuite) TearDownTest() {
}

func (s *blsTestSuite) TestPublicKey() {
	s.Run("successful public key derivation", func() {
		pubKey, err := s.BLSKey.PublicKey()
		s.NoError(err)
		s.NotNil(pubKey)
		// BLS public key should be SignatureSize bytes when serialized
		s.Equal(PublicKeySize, len(pubKey))
	})
}

func (s *blsTestSuite) TestSignMessage() {
	s.Run("successful message signing", func() {
		message := []byte("test message")
		signature, err := s.BLSKey.SignMessage(message)
		s.NoError(err)
		s.NotNil(signature)
		// BLS signature should be SignatureSize bytes when serialized
		s.Equal(SignatureSize, len(signature))

		// Get the public key to verify the signature
		publicKey, err := s.BLSKey.PublicKey()
		s.Require().NoError(err)

		// Verify the signature
		valid, err := VerifySignedMessage(signature, message, publicKey)
		s.NoError(err)
		s.True(valid, "Signature should be valid")
	})

	s.Run("empty message signing", func() {
		message := []byte("")
		signature, err := s.BLSKey.SignMessage(message)
		s.NoError(err) // BLS allows empty messages
		s.NotNil(signature)
		s.NotEmpty(signature)

		// Verify empty message signature
		publicKey, err := s.BLSKey.PublicKey()
		s.Require().NoError(err)

		valid, err := VerifySignedMessage(signature, message, publicKey)
		s.NoError(err)
		s.True(valid, "Empty message signature should be valid")
	})

	s.Run("different messages produce different signatures", func() {
		message1 := []byte("message 1")
		message2 := []byte("message 2")

		sig1, err := s.BLSKey.SignMessage(message1)
		s.Require().NoError(err)

		sig2, err := s.BLSKey.SignMessage(message2)
		s.Require().NoError(err)

		s.Require().False(bytes.Equal(sig1, sig2), "Different messages should produce different signatures")
	})

	s.Run("signature verification with wrong message fails", func() {
		correctMessage := []byte("correct message")
		wrongMessage := []byte("wrong message")

		signature, err := s.BLSKey.SignMessage(correctMessage)
		s.Require().NoError(err)

		publicKey, err := s.BLSKey.PublicKey()
		s.Require().NoError(err)

		// Should fail verification with wrong message
		valid, err := verify(signature, wrongMessage, publicKey, DSTSignature)
		s.Require().NoError(err)
		s.Require().False(valid, "Signature should not be valid for wrong message")
	})

	s.Run("signature verification with wrong public key fails", func() {
		message := []byte("test message")

		signature, err := s.BLSKey.SignMessage(message)
		s.Require().NoError(err)

		// Create another key to get a different public key
		anotherKey, err := New()
		s.Require().NoError(err)

		wrongPublicKey, err := anotherKey.PublicKey()
		s.Require().NoError(err)

		// Should fail verification with wrong public key
		valid, err := verify(signature, message, wrongPublicKey, DSTSignature)
		s.Require().NoError(err)
		s.Require().False(valid, "Signature should not be valid for wrong public key")
	})
}

func (s *blsTestSuite) TestSerialize() {
	s.Run("successful serialization", func() {
		serialized, err := s.BLSKey.Serialize()
		s.NoError(err)
		s.NotNil(serialized)
		// BLS secret key should be SecretKeySize bytes when serialized
		s.Equal(SecretKeySize, len(serialized))
	})

	s.Run("serialized key format validation", func() {
		serialized, err := s.BLSKey.Serialize()
		s.Require().NoError(err)

		// BLS secret key should be SecretKeySize bytes when serialized
		s.Equal(SecretKeySize, len(serialized))
	})
}

func (s *blsTestSuite) TestDeserialize() {
	// Create a key and serialize it for testing
	originalKey, err := New()
	s.Require().NoError(err)
	serializedKey, err := originalKey.Serialize()
	s.Require().NoError(err)

	s.Run("successful deserialization", func() {
		deserializedKey, err := Deserialize(serializedKey)
		s.NoError(err)
		s.NotNil(deserializedKey)
		s.NotNil(deserializedKey.secretKey)
	})

	s.Run("deserialized key produces same results", func() {
		deserializedKey, err := Deserialize(serializedKey)
		s.Require().NoError(err)

		// Public keys should match
		originalPubKey, err := originalKey.PublicKey()
		s.Require().NoError(err)

		deserializedPubKey, err := deserializedKey.PublicKey()
		s.Require().NoError(err)

		s.True(bytes.Equal(originalPubKey, deserializedPubKey))

		// Signatures should match
		message := []byte("test message")
		originalSig, err := originalKey.SignMessage(message)
		s.Require().NoError(err)

		deserializedSig, err := deserializedKey.SignMessage(message)
		s.Require().NoError(err)

		s.True(bytes.Equal(originalSig, deserializedSig))
	})

	s.Run("empty data deserialization", func() {
		deserializedKey, err := Deserialize([]byte{})
		s.Error(err)
		s.Nil(deserializedKey)
		s.ErrorContains(err, "failed to deserialize secret key")
	})

	s.Run("invalid data deserialization", func() {
		invalidData := []byte{0x01, 0x02, 0x03, 0x04} // Invalid BLS secret key data
		deserializedKey, err := Deserialize(invalidData)
		s.Error(err)
		s.Nil(deserializedKey)
		s.ErrorContains(err, "failed to deserialize secret key")
	})
}

func TestBLSTestSuite(t *testing.T) {
	suite.Run(t, new(blsTestSuite))
}
