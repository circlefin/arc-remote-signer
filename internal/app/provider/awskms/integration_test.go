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

package awskms

import (
	"context"
	"fmt"
	"testing"
	"time"

	awsSdkConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/circlefin/arc-remote-signer/internal/common/crypto/rand"
	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
)

const (
	testAwsInvalidArn       = "arn:aws:kms:us-east-1:000000000000:alias/invalid-arn"
	testAwsInvalidFormatArn = "arnawskms:us-east-1:000000000000:alias/invalid-arn"
)

type TestSuite struct {
	ctrl *gomock.Controller
	suite.Suite
	provider                  Provider
	providerImpl              provider
	providerImplWithMockCache provider
	kmsClient                 *kms.Client
}

func (suite *TestSuite) SetupTest() {
	suite.ctrl = gomock.NewController(suite.T())
	// Get default config.
	cfg := NewProviderConfig()
	var err error
	// Static credentials are required for localstack; without them the SDK falls back to EC2 IMDS which is unavailable in CI.
	awsCfg, err := awsSdkConfig.LoadDefaultConfig(context.Background(), awsSdkConfig.WithRegion(cfg.Localstack.Region), awsSdkConfig.WithBaseEndpoint(cfg.Localstack.Endpoint), awsSdkConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	suite.Require().NoError(err)

	// Init provider.
	pvd, err := New(context.Background(), cfg, awsCfg, nil)
	suite.Require().NoError(err)
	suite.provider = pvd

	clients, err := initClients(awsCfg, cfg.Arns, time.Duration(cfg.ConnectTimeout)*time.Millisecond)
	suite.Require().NoError(err)

	suite.providerImpl = provider{
		clients: clients,
	}
	suite.providerImplWithMockCache = provider{
		clients: clients,
	}
	suite.kmsClient = kms.NewFromConfig(awsCfg)
}

func (suite *TestSuite) TearDownTest() {
	suite.ctrl.Finish()
}

func (suite *TestSuite) TestNew() {
	awskmsCfg := NewProviderConfig()
	// Static credentials are required for localstack; without them the SDK falls back to EC2 IMDS which is unavailable in CI.
	awsCfg, err := awsSdkConfig.LoadDefaultConfig(context.Background(), awsSdkConfig.WithRegion(awskmsCfg.Localstack.Region), awsSdkConfig.WithBaseEndpoint(awskmsCfg.Localstack.Endpoint), awsSdkConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	suite.Require().NoError(err)

	suite.Run("success", func() {
		_, err = New(context.Background(), awskmsCfg, awsCfg, nil)
		suite.Require().NoError(err)
	})

	suite.Run("init fail", func() {
		arns := awskmsCfg.Arns
		defer func() {
			awskmsCfg.Arns = arns
		}()

		awskmsCfg.Arns = []string{}
		_, err = New(context.Background(), awskmsCfg, awsCfg, nil)
		suite.Require().Error(err)
	})
}

func (suite *TestSuite) TestGenerateDataKey() {
	suite.T().Run("success", func(_ *testing.T) {
		plainDataKey, cipherDataKey, ciphertextForRecipient, err := suite.provider.GenerateDataKey(context.Background())
		suite.Require().NoError(err)
		suite.Require().NotEmpty(plainDataKey)
		suite.Require().NotEmpty(cipherDataKey)
		suite.Require().Empty(ciphertextForRecipient)
	})
}

func (suite *TestSuite) TestDecrypt() {
	suite.T().Run("success", func(_ *testing.T) {
		// Generate data key.
		plainDataKey, cipherDataKey, ciphertextForRecipient, err := suite.provider.GenerateDataKey(context.Background())
		suite.Require().NoError(err)
		suite.Require().NotEmpty(plainDataKey)
		suite.Require().NotEmpty(cipherDataKey)
		suite.Require().Empty(ciphertextForRecipient)

		// Decrypt the ciphertext.
		plaintext, ciphertextForRecipient, err := suite.provider.Decrypt(context.Background(), cipherDataKey)
		suite.Require().NoError(err)
		suite.Require().NotEmpty(plaintext)
		suite.Require().Empty(ciphertextForRecipient)
	})

	suite.T().Run("empty ciphertext", func(_ *testing.T) {
		_, _, err := suite.provider.Decrypt(context.Background(), []byte{})
		suite.Require().Error(err)
	})

	suite.T().Run("decrypt fail", func(_ *testing.T) {
		_, _, err := suite.provider.Decrypt(context.Background(), []byte(rand.MustGenerateRandomString(40)))
		suite.Require().Error(err)
	})
}

func TestTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

// TestMultiRegionFailureOverSuite is a test suite for testing the multi-region failure over feature.
type TestMultiRegionFailureOverSuite struct {
	suite.Suite
	provider1 Provider // only with arn_1
	provider2 Provider // only with arn_2
}

func (suite *TestMultiRegionFailureOverSuite) SetupSuite() {
	// Get default config.
	cfg := NewProviderConfig()
	// Static credentials are required for localstack; without them the SDK falls back to EC2 IMDS which is unavailable in CI.
	awsCfg, err := awsSdkConfig.LoadDefaultConfig(context.Background(), awsSdkConfig.WithRegion(cfg.Localstack.Region), awsSdkConfig.WithBaseEndpoint(cfg.Localstack.Endpoint), awsSdkConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	suite.Require().NoError(err)
	cfg.ConnectTimeout = 1500

	// Get testing KEYs.
	arns := cfg.Arns
	suite.Require().NoError(err)

	// Init provider1 with arn_1.
	cfg.Arns = arns[:1]
	provider, err := New(context.Background(), cfg, awsCfg, nil)
	suite.Require().NoError(err)
	suite.provider1 = provider

	// Init provider2 with arn_2.
	cfg.Arns = arns[1:]
	provider, err = New(context.Background(), cfg, awsCfg, nil)
	suite.Require().NoError(err)
	suite.provider2 = provider
}

func (suite *TestMultiRegionFailureOverSuite) TestEncryptWithArn1DecryptWithArn2() {
	// This verifies that the data key ciphertext generated using arn1 can also be decrypted using arn2.
	plainDataKey, cipherDataKey, _, err := suite.provider1.GenerateDataKey(context.Background())
	suite.Require().NoError(err)

	plaintext, _, err := suite.provider2.Decrypt(context.Background(), cipherDataKey)
	suite.Require().NoError(err)
	suite.Require().Equal(plainDataKey, plaintext)
}

func (suite *TestMultiRegionFailureOverSuite) TestInvalidArnMultiRegionFailureOver() {
	// This verifies that when there is an issue with the key ARN, it can be switched to ARN2.
	// Get default config.
	cfg := NewProviderConfig()
	// Static credentials are required for localstack; without them the SDK falls back to EC2 IMDS which is unavailable in CI.
	awsCfg, err := awsSdkConfig.LoadDefaultConfig(context.Background(), awsSdkConfig.WithRegion(cfg.Localstack.Region), awsSdkConfig.WithBaseEndpoint(cfg.Localstack.Endpoint), awsSdkConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	suite.Require().NoError(err)

	// Get testing KEYs.
	arns := cfg.Arns
	suite.Require().NoError(err)

	suite.Run("withOneInvalidARNs", func() {
		cfg.Arns = append([]string{testAwsInvalidArn}, arns[:1]...)
		provider, err := New(context.Background(), cfg, awsCfg, nil)
		suite.Require().NoError(err)

		plainDataKey, cipherDataKey, _, err := provider.GenerateDataKey(context.Background())
		suite.Require().NoError(err)

		plaintext, _, err := provider.Decrypt(context.Background(), cipherDataKey)
		suite.Require().NoError(err)
		suite.Require().Equal(plainDataKey, plaintext)
	})

	suite.Run("withTwoInvalidARNs", func() {
		cfg.Arns = append([]string{testAwsInvalidArn, testAwsInvalidArn}, arns[:1]...)
		provider, err := New(context.Background(), cfg, awsCfg, nil)
		suite.Require().NoError(err)

		plainDataKey, cipherDataKey, _, err := provider.GenerateDataKey(context.Background())
		suite.Require().NoError(err)

		plaintext, _, err := provider.Decrypt(context.Background(), cipherDataKey)
		suite.Require().NoError(err)
		suite.Require().Equal(plainDataKey, plaintext)
	})
}

func (suite *TestMultiRegionFailureOverSuite) TestWithAllInvalidArn() {
	// Get default config.
	cfg := NewProviderConfig()
	cfg.ConnectTimeout = 1500
	// Static credentials are required for localstack; without them the SDK falls back to EC2 IMDS which is unavailable in CI.
	awsCfg, err := awsSdkConfig.LoadDefaultConfig(context.Background(), awsSdkConfig.WithRegion(cfg.Localstack.Region), awsSdkConfig.WithBaseEndpoint(cfg.Localstack.Endpoint), awsSdkConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	suite.Require().NoError(err)

	// Init provider with two invalid arn.
	cfg.Arns = []string{testAwsInvalidArn, testAwsInvalidArn}
	provider, err := New(context.Background(), cfg, awsCfg, nil)
	suite.Require().NoError(err)

	suite.Run("Encrypt", func() {
		// This validates that an "all the multi-region key are invalid" error will be returned when all key ARNs are invalidated during encryption.
		_, _, _, err = provider.GenerateDataKey(context.Background())
		suite.Require().ErrorContains(err, "all multi-region keys are invalid")
	})

	suite.Run("Decrypt", func() {
		// This validates that an "all the multi-region key are invalid" error will be returned when all key ARNs are invalidated during decryption.
		_, cipherDataKey, _, err := suite.provider1.GenerateDataKey(context.Background())
		suite.Require().NoError(err)

		_, _, err = provider.Decrypt(context.Background(), cipherDataKey)
		suite.Require().ErrorContains(err, "all multi-region keys are invalid")
	})
}

func (suite *TestMultiRegionFailureOverSuite) TestNewProviderWithInvalidFormatArn() {
	// This verifies that when creating a new provider, an error will be returned if an ARN that does not comply with the format is provided.
	cfg := NewProviderConfig()
	cfg.ConnectTimeout = 1500
	// Static credentials are required to prevent the SDK from attempting EC2 IMDS credential lookup in CI.
	awsCfg, err := awsSdkConfig.LoadDefaultConfig(context.Background(), awsSdkConfig.WithRegion(cfg.Localstack.Region), awsSdkConfig.WithBaseEndpoint(cfg.Localstack.Endpoint), awsSdkConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	suite.Require().NoError(err)

	cfg.Arns = []string{testAwsInvalidFormatArn}
	_, err = New(context.Background(), cfg, awsCfg, nil)
	suite.Require().EqualError(err, fmt.Sprintf("invalid arn(arn_%v))", 1))
}

func TestTestMultiRegionFailureOverSuite(t *testing.T) {
	suite.Run(t, new(TestMultiRegionFailureOverSuite))
}
