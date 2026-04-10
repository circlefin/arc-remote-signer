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

package app

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsSdkConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/circlefin/arc-remote-signer/internal/app/provider/awskms"
	enclave "github.com/circlefin/arc-remote-signer/internal/app/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/app/provider/secrets"
	"github.com/circlefin/arc-remote-signer/internal/app/service/signer"
	"github.com/circlefin/arc-remote-signer/internal/common/config"
	grpcServer "github.com/circlefin/arc-remote-signer/internal/common/grpc/server"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/internal/common/metric"
	"github.com/circlefin/arc-remote-signer/internal/common/telemetry"
)

// Config provides configuration for the app service.
type Config struct {
	// base config
	*config.BaseConfig `mapstructure:",squash"`
	// Public provides configuration for the public gRPC server.
	Public *PublicConfig `mapstructure:"public"`
	// Profiler provides configuration for the profiler.
	Profiler *ProfilerConfig `mapstructure:"profiler"`
	// Metrics provides Datadog statsd config for internal metric service.
	Metrics *metric.Config `mapstructure:"metrics"`
	// Telemetry provides OpenTelemetry config for internal telemetry service.
	Telemetry *telemetry.Config `mapstructure:"telemetry"`
	// Key provides configuration for the key service
	Service *ServiceConfig
	// Provider provide configuration for the http services each provider connects to
	Provider *ProviderConfig
}

// PublicConfig wraps server configuration to match YAML structure.
type PublicConfig struct {
	// Server provides gRPC server configuration.
	Server *grpcServer.Config `mapstructure:"server"`
}

// ProfilerConfig provides configuration for the profiler.
type ProfilerConfig struct {
	// Enabled enables the profiler.
	Enabled bool `mapstructure:"enabled"`
}

// GetName implements the config.ApplicationConfig interface.
func (c *Config) GetName() string {
	return "nitro-enclave-signer"
}

// ServiceConfig provides configuration for the service.
type ServiceConfig struct {
	Signer *signer.Config
}

// ProviderConfig lists the providers' config.
type ProviderConfig struct {
	Secrets *secrets.Config
	Enclave *enclave.ProviderConfig
	AWSKMS  *awskms.Config
}

// NewConfig returns a new Config with default dev (non-prod) environment.
func NewConfig() *Config {
	return &Config{
		BaseConfig: config.NewBaseConfig(),
		Public: &PublicConfig{
			Server: &grpcServer.Config{
				Host: "0.0.0.0",
				Port: 8080,
			},
		},
		Profiler: &ProfilerConfig{
			Enabled: false,
		},
		Metrics:   metric.NewConfig(),
		Telemetry: telemetry.NewConfig(),
		Service: &ServiceConfig{
			Signer: signer.NewConfig(),
		},
		Provider: &ProviderConfig{
			Secrets: secrets.NewConfig(),
			Enclave: enclave.NewProviderConfig(),
			AWSKMS:  awskms.NewProviderConfig(),
		},
	}
}

// MergeAwsConfigWithLocalstack will generate final awsConfig according endpoint and region in secrets config.
// If LocalstackEndpoint is empty in config, it will use default config of aws.
func MergeAwsConfigWithLocalstack(cfg *Config) (aws.Config, error) {
	awsEndpoint := cfg.Provider.Secrets.Localstack.Endpoint
	awsRegion := cfg.Provider.Secrets.Localstack.Region

	configOptions := []func(*awsSdkConfig.LoadOptions) error{}
	if awsRegion != "" {
		configOptions = append(configOptions, awsSdkConfig.WithRegion(awsRegion))
	}
	if awsEndpoint != "" {
		configOptions = append(configOptions, awsSdkConfig.WithBaseEndpoint(awsEndpoint))
		// Localstack does not validate credentials; inject static credentials to prevent
		// the SDK from attempting EC2 IMDS discovery in environments without AWS access.
		configOptions = append(configOptions, awsSdkConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	}

	return awsSdkConfig.LoadDefaultConfig(context.Background(), configOptions...)
}

func retrieveAWSConfig(ctx context.Context, cfg *Config, logger *logging.Logger) (aws.Config, error) {
	if cfg.BaseConfig == nil || cfg.Provider.Secrets == nil || cfg.Provider.Secrets.Localstack == nil {
		return aws.Config{}, errors.New("secrets config unavailable")
	}

	if (cfg.Env == config.Dev || cfg.Env == config.QA) &&
		(cfg.Provider.Secrets.Localstack.Enabled && cfg.Provider.Secrets.Localstack.Endpoint != "") {
		logger.Info(ctx, "Using localstack aws config...", nil)
		return MergeAwsConfigWithLocalstack(cfg)
	}
	logger.Info(ctx, "Using standard aws config...", nil)
	return awsSdkConfig.LoadDefaultConfig(ctx)
}
