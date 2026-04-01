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
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/crypto/rand"
	"github.com/stretchr/testify/suite"
)

type CryptoTestSuite struct {
	suite.Suite
}

func (suite *CryptoTestSuite) SetupSuite() {
}

func (suite *CryptoTestSuite) TestHeaderDeserialize() {
	oldHeader := header{
		CipherKey:  []byte(rand.MustGenerateRandomString(10)),
		CipherData: []byte(rand.MustGenerateRandomString(10)),
		Nonce:      []byte(rand.MustGenerateRandomString(10)),
	}

	oldtext, err := oldHeader.MarshalBinary()
	suite.Require().NoError(err)

	newHeader := header{}
	err = newHeader.UnmarshalBinary(oldtext)
	suite.Require().NoError(err)
	suite.Require().Equal(newHeader.CipherKey, oldHeader.CipherKey)
	suite.Require().Equal(newHeader.CipherData, oldHeader.CipherData)
	suite.Require().Equal(newHeader.Nonce, oldHeader.Nonce)
}

func (suite *CryptoTestSuite) TestCryptoHeaderDeserializeWithMissingKey() {
	// This test verifies that oldtext serialized with old cryptoHeader can deserialize with new cryptoHeader which missing some keys.
	oldHeader := header{
		CipherKey:  []byte(rand.MustGenerateRandomString(10)),
		CipherData: []byte(rand.MustGenerateRandomString(10)),
		Nonce:      []byte(rand.MustGenerateRandomString(10)),
	}

	oldtext, err := oldHeader.MarshalBinary()
	suite.Require().NoError(err)

	var newHeader newHeaderMissingKey
	err = newHeader.UnmarshalBinary(oldtext)
	suite.Require().NoError(err)
	suite.Require().Equal(newHeader.CipherData, oldHeader.CipherData)
	suite.Require().Equal(newHeader.Nonce, oldHeader.Nonce)
}

func (suite *CryptoTestSuite) TestCryptoHeaderDeserializeWithAdditionalKey() {
	// This test verifies that the old serialized text can still be deserialized even if the new struct has an additional key.
	oldHeader := header{
		CipherKey:  []byte(rand.MustGenerateRandomString(10)),
		CipherData: []byte(rand.MustGenerateRandomString(10)),
		Nonce:      []byte(rand.MustGenerateRandomString(10)),
	}

	oldtext, err := oldHeader.MarshalBinary()
	suite.Require().NoError(err)

	var newHeader newHeaderWithAdditionalKey
	err = newHeader.UnmarshalBinary(oldtext)
	suite.Require().NoError(err)
	suite.Require().Equal(newHeader.CipherKey, oldHeader.CipherKey)
	suite.Require().Equal(newHeader.CipherData, oldHeader.CipherData)
	suite.Require().Equal(newHeader.Nonce, oldHeader.Nonce)
}

func TestCryptoTestSuite(t *testing.T) {
	suite.Run(t, new(CryptoTestSuite))
}

type newHeaderMissingKey struct {
	CipherData []byte
	Nonce      []byte
}

func (h *newHeaderMissingKey) UnmarshalBinary(data []byte) error {
	type headerAlias newHeaderMissingKey
	return gob.NewDecoder(bytes.NewReader(data)).Decode((*headerAlias)(h))
}

type newHeaderWithAdditionalKey struct {
	CipherKey     []byte
	CipherData    []byte
	Nonce         []byte
	AdditionalKey string
}

func (h *newHeaderWithAdditionalKey) UnmarshalBinary(data []byte) error {
	type headerAlias newHeaderWithAdditionalKey
	return gob.NewDecoder(bytes.NewReader(data)).Decode((*headerAlias)(h))
}
