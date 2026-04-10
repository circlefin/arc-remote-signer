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

package aes

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSerialize_RoundTrip(t *testing.T) {
	key, err := New()
	require.NoError(t, err)
	serialized, err := key.Serialize()
	require.NoError(t, err)
	deserialized, err := Deserialize(serialized)
	require.NoError(t, err)
	require.Equal(t, key, deserialized)
}

func TestDeserialize_InvalidKeySize(t *testing.T) {
	invalidData := []byte{0x01, 0x02, 0x03, 0x04}
	deserialized, err := Deserialize(invalidData)
	require.ErrorContains(t, err, "invalid key size")
	require.Nil(t, deserialized)
}

func TestPublicKey_NotImplemented(t *testing.T) {
	key, err := New()
	require.NoError(t, err)
	publicKey, err := key.PublicKey()
	require.Empty(t, publicKey)
	require.ErrorContains(t, err, "not implemented")
}

func TestSignMessage_NotImplemented(t *testing.T) {
	key, err := New()
	require.NoError(t, err)
	signature, err := key.SignMessage([]byte("test message"))
	require.Empty(t, signature)
	require.ErrorContains(t, err, "not implemented")
}
