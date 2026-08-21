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

//go:build !prod

package app

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsSdkConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	enclaveProvider "github.com/circlefin/arc-remote-signer/internal/app/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/app/provider/secrets"
	"github.com/circlefin/arc-remote-signer/internal/common/config"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"google.golang.org/grpc"
)

func applyBuildPolicy(*Config) {
	// The development build uses the supplied configuration.
}

// NewAWSKMSConfig returns development KMS defaults.
func NewAWSKMSConfig() *AWSKMSConfig {
	return &AWSKMSConfig{
		Localstack: &AWSKMSLocalstackConfig{Enabled: true},
		Arns: []string{
			"arn:aws:kms:us-east-1:000000000000:alias/dev-multi-region-crypto",
			"arn:aws:kms:us-west-2:000000000000:alias/dev-multi-region-crypto",
		},
	}
}

// NewConfig returns development configuration.
func NewConfig() *Config {
	return newConfig(config.NewBaseConfig(), secrets.NewConfig(), NewAWSKMSConfig())
}

func newRuntimeEnclave(cfg *enclaveProvider.ProviderConfig) (pb.EnclaveServiceClient, *grpc.ClientConn, error) {
	return enclaveProvider.New(cfg)
}

func loadRuntimeAWSConfig(ctx context.Context, cfg *Config, logger *logging.Logger) (aws.Config, error) {
	return retrieveAWSConfig(ctx, cfg, logger)
}

// MergeAwsConfigWithLocalstack creates an AWS configuration for LocalStack.
func MergeAwsConfigWithLocalstack(cfg *Config) (aws.Config, error) {
	awsEndpoint := cfg.Provider.Secrets.Localstack.Endpoint
	awsRegion := cfg.Provider.Secrets.Localstack.Region

	configOptions := []func(*awsSdkConfig.LoadOptions) error{}
	if awsRegion != "" {
		configOptions = append(configOptions, awsSdkConfig.WithRegion(awsRegion))
	}
	if awsEndpoint != "" {
		configOptions = append(
			configOptions,
			awsSdkConfig.WithBaseEndpoint(awsEndpoint),
			awsSdkConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				"test",
				"test",
				"dev-session-token-placeholder",
			)),
		)
	}

	return awsSdkConfig.LoadDefaultConfig(context.Background(), configOptions...)
}

func retrieveAWSConfig(ctx context.Context, cfg *Config, logger *logging.Logger) (aws.Config, error) {
	if cfg.BaseConfig == nil || cfg.Provider.Secrets == nil || cfg.Provider.Secrets.Localstack == nil {
		return aws.Config{}, errors.New("secrets configuration is unavailable")
	}

	if (cfg.Env == config.Dev || cfg.Env == config.QA) &&
		cfg.Provider.Secrets.Localstack.Enabled && cfg.Provider.Secrets.Localstack.Endpoint != "" {
		logger.Info(ctx, "The signer uses the LocalStack AWS configuration.", nil)
		return MergeAwsConfigWithLocalstack(cfg)
	}
	logger.Info(ctx, "The signer uses the standard AWS configuration.", nil)
	return awsSdkConfig.LoadDefaultConfig(ctx)
}
