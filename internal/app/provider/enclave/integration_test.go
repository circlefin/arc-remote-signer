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

//go:build integration

package enclave

import (
	"context"
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/crypto/rand"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type integrationTestSuite struct {
	suite.Suite

	client                     pb.EnclaveServiceClient
	conn                       *grpc.ClientConn
	testingEncryptedDataKey    []byte
	testingEncryptedPrivateKey []byte
	testingNonce               []byte
	testingPubKey              []byte
}

func (suite *integrationTestSuite) SetupSuite() {
	config := NewProviderConfig()
	client, conn, err := New(config)
	suite.Require().NoError(err)
	suite.client = client
	suite.conn = conn
}

func (suite *integrationTestSuite) TearDownSuite() {
	err := suite.conn.Close()
	suite.Require().NoError(err)
}

func (suite *integrationTestSuite) SetupTest() {
	suite.testingEncryptedDataKey = rand.MustGenerateRandomBytes(32)
	result, err := suite.client.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		Algorithm:               pb.Algorithm_ALGORITHM_ED25519,
		EnclaveEncryptedDataKey: suite.testingEncryptedDataKey,
	})
	suite.Require().NoError(err)
	suite.Require().NotNil(result)
	suite.Require().NotEmpty(result.PublicKey)
	suite.Require().NotEmpty(result.EncryptedPrivateKey)
	suite.Require().NotEmpty(result.Nonce)

	suite.testingEncryptedPrivateKey = result.EncryptedPrivateKey
	suite.testingNonce = result.Nonce
	suite.testingPubKey = result.PublicKey
}

func (suite *integrationTestSuite) TestGenerateKey() {
	suite.Run("success", func() {
		result, err := suite.client.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			Algorithm:               pb.Algorithm_ALGORITHM_ED25519,
			EnclaveEncryptedDataKey: suite.testingEncryptedDataKey,
		})
		suite.Require().NoError(err)
		suite.Require().NotNil(result)
		suite.Require().NotEmpty(result.PublicKey)
		suite.Require().NotEmpty(result.EncryptedPrivateKey)
		suite.Require().NotEmpty(result.Nonce)
	})
	suite.Run("invalid algorithm", func() {
		result, err := suite.client.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			Algorithm:               pb.Algorithm_ALGORITHM_UNSPECIFIED,
			EnclaveEncryptedDataKey: suite.testingEncryptedDataKey,
		})
		suite.Require().Error(err)
		suite.Require().Nil(result)
		suite.Require().Equal(codes.InvalidArgument, status.Code(err))
	})
}

func (suite *integrationTestSuite) TestGetPublicKey() {
	suite.Run("success", func() {
		result, err := suite.client.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{
			Algorithm: pb.Algorithm_ALGORITHM_ED25519,
			EncryptedKeyMaterial: &pb.EncryptedKeyMaterial{
				EncryptedPrivateKey:     suite.testingEncryptedPrivateKey,
				EnclaveEncryptedDataKey: suite.testingEncryptedDataKey,
				Nonce:                   suite.testingNonce,
			},
		})
		suite.Require().NoError(err)
		suite.Require().NotNil(result)
		suite.Require().NotEmpty(result.PublicKey)
		suite.Require().Equal(suite.testingPubKey, result.PublicKey)
	})
}

func (suite *integrationTestSuite) TestSignMessage() {
	suite.Run("success", func() {
		result, err := suite.client.SignMessage(context.Background(), &pb.SignMessageRequest{
			Algorithm: pb.Algorithm_ALGORITHM_ED25519,
			EncryptedKeyMaterial: &pb.EncryptedKeyMaterial{
				EncryptedPrivateKey:     suite.testingEncryptedPrivateKey,
				EnclaveEncryptedDataKey: suite.testingEncryptedDataKey,
				Nonce:                   suite.testingNonce,
			},
			Message: []byte("test message"),
		})
		suite.Require().NoError(err)
		suite.Require().NotNil(result)
		suite.Require().NotEmpty(result.Signature)
	})
	suite.Run("invalid algorithm", func() {
		result, err := suite.client.SignMessage(context.Background(), &pb.SignMessageRequest{
			Algorithm: pb.Algorithm_ALGORITHM_UNSPECIFIED,
		})
		suite.Require().Error(err)
		suite.Require().Nil(result)
		suite.Require().Equal(codes.InvalidArgument, status.Code(err))
	})
}

func (suite *integrationTestSuite) TestGetAttestation() {
	// Local/CI environments do not run enclave service inside Nitro Enclave.
	// Therefore this integration test can only validate the "enclave not enabled"
	// behavior, which should return FailedPrecondition.
	resp, err := suite.client.GetAttestation(context.Background(), &pb.GetAttestationRequest{})
	suite.Require().Error(err)
	suite.Require().Equal(codes.FailedPrecondition, status.Code(err))
	suite.Require().Nil(resp)
}

func TestEnclaveProviderIntegration(t *testing.T) {
	suite.Run(t, new(integrationTestSuite))
}
