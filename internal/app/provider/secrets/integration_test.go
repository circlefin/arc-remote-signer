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

package secrets

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsSdkConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/circlefin/arc-remote-signer/internal/common/crypto/rand"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type testSuite struct {
	suite.Suite
	awsCfg   aws.Config
	provider *ProviderImpl

	secretName  string
	secretID    string
	secretValue []byte
}

func (suite *testSuite) SetupSuite() {
	cfg := NewConfig()
	var err error
	// Static credentials are required for localstack; without them the SDK falls back to EC2 IMDS which is unavailable in CI.
	suite.awsCfg, err = awsSdkConfig.LoadDefaultConfig(context.Background(), awsSdkConfig.WithRegion(cfg.Localstack.Region), awsSdkConfig.WithBaseEndpoint(cfg.Localstack.Endpoint), awsSdkConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	suite.Require().NoError(err)
	suite.provider = New(suite.awsCfg)
}

func (suite *testSuite) SetupTest() {
	suite.secretName = uuid.Must(uuid.NewV7()).String()
	suite.secretValue = rand.MustGenerateRandomBytes(32)
	var err error
	suite.secretID, err = suite.CreateForTesting(context.Background(), suite.secretName, suite.secretValue)
	suite.Require().NoError(err)
	suite.Require().NotEmpty(suite.secretID)
}

func (suite *testSuite) TestGet() {
	suite.T().Run("success", func(_ *testing.T) {
		secret, err := suite.provider.Get(context.Background(), suite.secretID)
		suite.Require().NoError(err)
		suite.Require().Equal(suite.secretValue, secret)
	})
	suite.T().Run("secret not found", func(_ *testing.T) {
		secret, err := suite.provider.Get(context.Background(), uuid.Must(uuid.NewV7()).String())
		suite.Require().NoError(err)
		suite.Require().Empty(secret)
	})
}

func (suite *testSuite) TestUpdate() {
	suite.T().Run("success", func(_ *testing.T) {
		secretValue2 := rand.MustGenerateRandomBytes(32)
		ID, err := suite.provider.Update(context.Background(), suite.secretID, secretValue2)
		suite.Require().NoError(err)

		secret, err := suite.provider.Get(context.Background(), ID)
		suite.Require().NoError(err)
		suite.Require().Equal(secretValue2, secret)
	})
	suite.T().Run("secret not found", func(_ *testing.T) {
		ID, err := suite.provider.Update(context.Background(), uuid.Must(uuid.NewV7()).String(), rand.MustGenerateRandomBytes(32))
		suite.Require().Error(err)
		suite.Require().Empty(ID)
	})
}

func (suite *testSuite) CreateForTesting(ctx context.Context, name string, secret []byte) (secretID string, err error) {
	sm := secretsmanager.NewFromConfig(suite.awsCfg)
	resp, err := sm.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(name),
		SecretString: aws.String(base64.StdEncoding.EncodeToString(secret)),
	})
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to create secret: %v", err)
	}
	return *resp.ARN, nil
}

func TestProviderTestSuite(t *testing.T) {
	suite.Run(t, new(testSuite))
}
