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

	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// testKMSKeyARN is the LocalStack multi-region key alias created by
// deployments/localstack_scripts/create-kms-keys.sh.
const testKMSKeyARN = "arn:aws:kms:us-east-1:000000000000:alias/dev-multi-region-crypto"

type integrationTestSuite struct {
	suite.Suite

	client        pb.EnclaveServiceClient
	conn          *grpc.ClientConn
	testEnvelope  *pb.SecretEnvelope
	testingPubKey []byte
}

func (suite *integrationTestSuite) SetupSuite() {
	config := NewProviderConfig()
	client, conn, err := New(config)
	suite.Require().NoError(err)
	suite.client = client
	suite.conn = conn

	// The enclave now mints its own data key via KMS, so it must be
	// initialized with credentials and the LocalStack KMS ARN before any
	// GenerateKey/read RPC. Initialize is idempotent, so running it once per
	// suite is sufficient. Credentials match the LocalStack values in
	// docker-compose; session_token is a placeholder to satisfy the proto's
	// min_len validation (LocalStack ignores it).
	_, err = suite.client.Initialize(context.Background(), &pb.InitializeRequest{
		Credentials: &pb.AwsCredentials{
			AccessKeyId:     "foo",
			SecretAccessKey: "bar",
			SessionToken:    "session",
			Region:          "us-east-1",
		},
		KmsKeyArns:           []string{testKMSKeyARN},
		KmsLocalstackEnabled: true,
	})
	suite.Require().NoError(err)
}

func (suite *integrationTestSuite) TearDownSuite() {
	err := suite.conn.Close()
	suite.Require().NoError(err)
}

func (suite *integrationTestSuite) SetupTest() {
	result, err := suite.client.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		Algorithm: pb.Algorithm_ALGORITHM_ED25519,
	})
	suite.Require().NoError(err)
	suite.Require().NotNil(result)
	suite.Require().NotEmpty(result.PublicKey)
	suite.Require().NotNil(result.SecretEnvelope)

	suite.testEnvelope = result.SecretEnvelope
	suite.testingPubKey = result.PublicKey
}

func (suite *integrationTestSuite) TestGenerateKey() {
	suite.Run("success", func() {
		result, err := suite.client.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			Algorithm: pb.Algorithm_ALGORITHM_ED25519,
		})
		suite.Require().NoError(err)
		suite.Require().NotNil(result)
		suite.Require().NotEmpty(result.PublicKey)
		suite.Require().NotNil(result.SecretEnvelope)
		suite.Require().NotEmpty(result.SecretEnvelope.KmsEncryptedDataKey)
		suite.Require().NotEmpty(result.SecretEnvelope.EncryptedPrivateKey)
		suite.Require().NotEmpty(result.SecretEnvelope.Nonce)
	})
	suite.Run("invalid algorithm", func() {
		result, err := suite.client.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			Algorithm: pb.Algorithm_ALGORITHM_UNSPECIFIED,
		})
		suite.Require().Error(err)
		suite.Require().Nil(result)
		suite.Require().Equal(codes.InvalidArgument, status.Code(err))
	})
}

func (suite *integrationTestSuite) TestGetPublicKey() {
	suite.Run("success", func() {
		result, err := suite.client.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{
			SecretEnvelope: suite.testEnvelope,
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
			SecretEnvelope: suite.testEnvelope,
			Message:        []byte("test message"),
		})
		suite.Require().NoError(err)
		suite.Require().NotNil(result)
		suite.Require().NotEmpty(result.Signature)
	})
	suite.Run("invalid algorithm", func() {
		result, err := suite.client.SignMessage(context.Background(), &pb.SignMessageRequest{
			SecretEnvelope: &pb.SecretEnvelope{
				Algorithm:           pb.Algorithm_ALGORITHM_UNSPECIFIED,
				KmsEncryptedDataKey: suite.testEnvelope.KmsEncryptedDataKey,
				EncryptedPrivateKey: suite.testEnvelope.EncryptedPrivateKey,
				Nonce:               suite.testEnvelope.Nonce,
			},
			Message: []byte("test message"),
		})
		suite.Require().Error(err)
		suite.Require().Nil(result)
		suite.Require().Equal(codes.InvalidArgument, status.Code(err))
	})
}

func TestEnclaveProviderIntegration(t *testing.T) {
	suite.Run(t, new(integrationTestSuite))
}
