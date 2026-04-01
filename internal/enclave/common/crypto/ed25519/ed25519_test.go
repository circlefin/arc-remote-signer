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

package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ed25519TestSuite struct {
	suite.Suite
	Ed25519Key *Key
}

func (s *ed25519TestSuite) SetupTest() {
	ed25519Key, err := New()
	s.Require().NoError(err)
	s.Ed25519Key = ed25519Key
}

func (s *ed25519TestSuite) TearDownTest() {
}

func (s *ed25519TestSuite) TestNew() {
	s.Run("successful key generation", func() {
		key, err := New()
		s.NoError(err)
		s.NotNil(key)
		s.NotNil(key.privateKey)
		s.Equal(ed25519.PrivateKeySize, len(key.privateKey))
	})

	s.Run("generated keys are unique", func() {
		key1, err := New()
		s.Require().NoError(err)

		key2, err := New()
		s.Require().NoError(err)

		// Private keys should be different
		s.False(bytes.Equal(key1.privateKey, key2.privateKey))

		// Public keys should be different
		pubKey1, err := key1.PublicKey()
		s.Require().NoError(err)

		pubKey2, err := key2.PublicKey()
		s.Require().NoError(err)

		s.False(bytes.Equal(pubKey1, pubKey2))
	})
}

func (s *ed25519TestSuite) TestPublicKey() {
	s.Run("successful public key derivation", func() {
		pubKey, err := s.Ed25519Key.PublicKey()
		s.NoError(err)
		s.NotNil(pubKey)
		// Ed25519 public key should be PublicKeySize bytes
		s.Equal(ed25519.PublicKeySize, len(pubKey))
	})

	s.Run("public key is deterministic", func() {
		pubKey1, err := s.Ed25519Key.PublicKey()
		s.Require().NoError(err)

		pubKey2, err := s.Ed25519Key.PublicKey()
		s.Require().NoError(err)

		s.True(bytes.Equal(pubKey1, pubKey2), "Public key should be deterministic")
	})
}

func (s *ed25519TestSuite) TestSignMessage() {
	s.Run("successful message signing", func() {
		message := []byte("test message")
		signature, err := s.Ed25519Key.SignMessage(message)
		s.NoError(err)
		s.NotNil(signature)
		// Ed25519 signature should be SignatureSize bytes
		s.Equal(ed25519.SignatureSize, len(signature))

		// Get the public key to verify the signature
		publicKey, err := s.Ed25519Key.PublicKey()
		s.Require().NoError(err)

		// Verify the signature
		valid, err := VerifySignedMessage(signature, message, publicKey)
		s.NoError(err)
		s.True(valid, "Signature should be valid")
	})

	s.Run("empty message signing", func() {
		message := []byte("")
		signature, err := s.Ed25519Key.SignMessage(message)
		s.NoError(err) // Ed25519 allows empty messages
		s.NotNil(signature)
		s.Equal(ed25519.SignatureSize, len(signature))

		// Verify empty message signature
		publicKey, err := s.Ed25519Key.PublicKey()
		s.Require().NoError(err)

		valid, err := VerifySignedMessage(signature, message, publicKey)
		s.NoError(err)
		s.True(valid, "Empty message signature should be valid")
	})

	s.Run("different messages produce different signatures", func() {
		message1 := []byte("message 1")
		message2 := []byte("message 2")

		sig1, err := s.Ed25519Key.SignMessage(message1)
		s.Require().NoError(err)

		sig2, err := s.Ed25519Key.SignMessage(message2)
		s.Require().NoError(err)

		s.False(bytes.Equal(sig1, sig2), "Different messages should produce different signatures")
	})

	s.Run("same message produces same signature", func() {
		message := []byte("test message")

		sig1, err := s.Ed25519Key.SignMessage(message)
		s.Require().NoError(err)

		sig2, err := s.Ed25519Key.SignMessage(message)
		s.Require().NoError(err)

		s.True(bytes.Equal(sig1, sig2), "Same message should produce same signature (Ed25519 is deterministic)")
	})

	s.Run("large message signing", func() {
		// Create a 1MB message
		largeMessage := make([]byte, 1024*1024)
		for i := range largeMessage {
			largeMessage[i] = byte(i % 256)
		}

		signature, err := s.Ed25519Key.SignMessage(largeMessage)
		s.NoError(err)
		s.NotNil(signature)
		s.Equal(ed25519.SignatureSize, len(signature))

		// Verify the signature
		publicKey, err := s.Ed25519Key.PublicKey()
		s.Require().NoError(err)

		valid, err := VerifySignedMessage(signature, largeMessage, publicKey)
		s.NoError(err)
		s.True(valid, "Large message signature should be valid")
	})
}

func (s *ed25519TestSuite) TestVerifySignedMessage() {
	message := []byte("test message")

	signature, err := s.Ed25519Key.SignMessage(message)
	s.Require().NoError(err)

	publicKey, err := s.Ed25519Key.PublicKey()
	s.Require().NoError(err)

	s.Run("valid signature verification", func() {
		valid, err := VerifySignedMessage(signature, message, publicKey)
		s.NoError(err)
		s.True(valid)
	})

	s.Run("signature verification with wrong message fails", func() {
		wrongMessage := []byte("wrong message")
		valid, err := VerifySignedMessage(signature, wrongMessage, publicKey)
		s.NoError(err)
		s.False(valid, "Signature should not be valid for wrong message")
	})

	s.Run("signature verification with wrong public key fails", func() {
		// Create another key to get a different public key
		anotherKey, err := New()
		s.Require().NoError(err)

		wrongPublicKey, err := anotherKey.PublicKey()
		s.Require().NoError(err)

		valid, err := VerifySignedMessage(signature, message, wrongPublicKey)
		s.NoError(err)
		s.False(valid, "Signature should not be valid for wrong public key")
	})

	s.Run("signature verification with tampered signature fails", func() {
		// Tamper with the signature
		tamperedSignature := make([]byte, len(signature))
		copy(tamperedSignature, signature)
		tamperedSignature[0] ^= 0xFF // Flip all bits in first byte

		valid, err := VerifySignedMessage(tamperedSignature, message, publicKey)
		s.NoError(err)
		s.False(valid, "Tampered signature should not be valid")
	})

	s.Run("invalid public key size", func() {
		invalidPublicKey := []byte("too short")
		valid, err := VerifySignedMessage(signature, message, invalidPublicKey)
		s.Error(err)
		s.False(valid)
		s.ErrorContains(err, "invalid public key size")
	})

	s.Run("invalid signature size", func() {
		invalidSignature := []byte("too short")
		valid, err := VerifySignedMessage(invalidSignature, message, publicKey)
		s.Error(err)
		s.False(valid)
		s.ErrorContains(err, "invalid signature size")
	})
}

func (s *ed25519TestSuite) TestSerialize() {
	s.Run("successful serialization", func() {
		serialized, err := s.Ed25519Key.Serialize()
		s.NoError(err)
		s.NotNil(serialized)
		// Ed25519 private key should be PrivateKeySize bytes when serialized
		s.Equal(ed25519.PrivateKeySize, len(serialized))
	})

	s.Run("serialization creates a copy", func() {
		serialized, err := s.Ed25519Key.Serialize()
		s.Require().NoError(err)

		// Modify the serialized data
		original := make([]byte, len(serialized))
		copy(original, serialized)
		serialized[0] ^= 0xFF

		// Original key should still work
		signature, err := s.Ed25519Key.SignMessage([]byte("test"))
		s.NoError(err)
		s.NotNil(signature)

		// Verify that the serialized data was indeed a copy
		s.False(bytes.Equal(serialized, s.Ed25519Key.privateKey[:1]))
	})
}

func (s *ed25519TestSuite) TestDeserialize() {
	// Create a key and serialize it for testing
	originalKey, err := New()
	s.Require().NoError(err)
	serializedKey, err := originalKey.Serialize()
	s.Require().NoError(err)

	s.Run("successful deserialization", func() {
		deserializedKey, err := Deserialize(serializedKey)
		s.NoError(err)
		s.NotNil(deserializedKey)
		s.NotNil(deserializedKey.privateKey)
		s.Equal(ed25519.PrivateKeySize, len(deserializedKey.privateKey))
	})

	s.Run("deserialized key produces same results", func() {
		deserializedKey, err := Deserialize(serializedKey)
		s.Require().NoError(err)

		// Public keys should match
		originalPubKey, err := originalKey.PublicKey()
		s.Require().NoError(err)

		deserializedPubKey, err := deserializedKey.PublicKey()
		s.Require().NoError(err)

		s.True(bytes.Equal(originalPubKey, deserializedPubKey), "Public keys should match")

		// Signatures should match (Ed25519 is deterministic)
		message := []byte("test message")
		originalSig, err := originalKey.SignMessage(message)
		s.Require().NoError(err)

		deserializedSig, err := deserializedKey.SignMessage(message)
		s.Require().NoError(err)

		s.True(bytes.Equal(originalSig, deserializedSig), "Signatures should match")
	})

	s.Run("empty data deserialization", func() {
		deserializedKey, err := Deserialize([]byte{})
		s.Error(err)
		s.Nil(deserializedKey)
		s.ErrorContains(err, "invalid key size")
	})

	s.Run("invalid size data deserialization", func() {
		// Too short
		shortData := make([]byte, ed25519.PrivateKeySize-1)
		deserializedKey, err := Deserialize(shortData)
		s.Error(err)
		s.Nil(deserializedKey)
		s.ErrorContains(err, "invalid key size")

		// Too long
		longData := make([]byte, ed25519.PrivateKeySize+1)
		deserializedKey, err = Deserialize(longData)
		s.Error(err)
		s.Nil(deserializedKey)
		s.ErrorContains(err, "invalid key size")
	})
}

func (s *ed25519TestSuite) TestRoundTrip() {
	s.Run("serialize and deserialize round trip", func() {
		// Create a new key
		originalKey, err := New()
		s.Require().NoError(err)

		// Get original public key
		originalPubKey, err := originalKey.PublicKey()
		s.Require().NoError(err)

		// Serialize the key
		serialized, err := originalKey.Serialize()
		s.Require().NoError(err)

		// Deserialize the key
		deserializedKey, err := Deserialize(serialized)
		s.Require().NoError(err)

		// Get deserialized public key
		deserializedPubKey, err := deserializedKey.PublicKey()
		s.Require().NoError(err)

		// Public keys should match
		s.True(bytes.Equal(originalPubKey, deserializedPubKey))

		// Test signing with both keys
		message := []byte("round trip test message")

		originalSig, err := originalKey.SignMessage(message)
		s.Require().NoError(err)

		deserializedSig, err := deserializedKey.SignMessage(message)
		s.Require().NoError(err)

		// Signatures should be identical (Ed25519 is deterministic)
		s.True(bytes.Equal(originalSig, deserializedSig))

		// Both signatures should verify with either public key
		valid, err := VerifySignedMessage(originalSig, message, originalPubKey)
		s.Require().NoError(err)
		s.True(valid)

		valid, err = VerifySignedMessage(deserializedSig, message, deserializedPubKey)
		s.Require().NoError(err)
		s.True(valid)
	})
}

func TestEd25519TestSuite(t *testing.T) {
	suite.Run(t, new(ed25519TestSuite))
}
