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

package keystore

import (
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto/bls"
	"github.com/stretchr/testify/suite"
)

// KeystoreTestSuite is the test suite for the keystore provider.
type KeystoreTestSuite struct {
	suite.Suite
	provider *ProviderImpl
}

// SetupTest sets up the test environment.
func (suite *KeystoreTestSuite) SetupTest() {
	provider := New()
	suite.provider = provider
}

func (suite *KeystoreTestSuite) TestKeystoreProvider() {
	suite.Run("SetAndGet", func() {
		ciphertext := []byte("test_ciphertext")
		secretKey, err := bls.New()
		suite.Require().NoError(err)

		err = suite.provider.Set(ciphertext, secretKey)
		suite.Require().NoError(err)

		retrievedKey := suite.provider.Get(ciphertext)
		suite.Require().NotNil(retrievedKey)
		suite.Equal(secretKey, retrievedKey)
	})

	suite.Run("GetNonExistentKey", func() {
		ciphertext := []byte("non_existent_ciphertext")
		retrievedKey := suite.provider.Get(ciphertext)
		suite.Require().Nil(retrievedKey)
	})

	suite.Run("SetMultipleKeys", func() {
		ciphertext1 := []byte("ciphertext1")
		secretKey1, err := bls.New()
		suite.Require().NoError(err)
		ciphertext2 := []byte("ciphertext2")
		secretKey2, err := bls.New()
		suite.Require().NoError(err)

		err1 := suite.provider.Set(ciphertext1, secretKey1)
		suite.Require().NoError(err1)
		err2 := suite.provider.Set(ciphertext2, secretKey2)
		suite.Require().NoError(err2)

		retrievedKey1 := suite.provider.Get(ciphertext1)
		suite.Require().NotNil(retrievedKey1)
		suite.Equal(secretKey1, retrievedKey1)

		retrievedKey2 := suite.provider.Get(ciphertext2)
		suite.Require().NotNil(retrievedKey2)
		suite.Equal(secretKey2, retrievedKey2)
	})

	suite.Run("ConcurrentAccess", func() {
		ciphertext := []byte("concurrent_ciphertext")
		secretKey, err := bls.New()
		suite.Require().NoError(err)

		err = suite.provider.Set(ciphertext, secretKey)
		suite.Require().NoError(err)

		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func() {
				retrievedKey := suite.provider.Get(ciphertext)
				var result bool
				if retrievedKey != nil && secretKey == retrievedKey {
					result = true
				} else {
					result = false
				}
				done <- result
			}()
		}
		results := make([]bool, 10)
		for i := 0; i < 10; i++ {
			results[i] = <-done
		}
		for _, result := range results {
			suite.Require().True(result, "Concurrent access test failed")
		}
	})
}

// TestKeystoreProvider runs the test suite.
func TestKeystoreProvider(t *testing.T) {
	suite.Run(t, new(KeystoreTestSuite))
}
