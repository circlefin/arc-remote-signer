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
	enclave "github.com/circlefin/arc-remote-signer/internal/app/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/app/provider/secrets"
	signerv1 "github.com/circlefin/arc-remote-signer/internal/app/service/signer/v1"
	"github.com/circlefin/arc-remote-signer/internal/common/config"
	grpcServer "github.com/circlefin/arc-remote-signer/internal/common/grpc/server"
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
	Signer *signerv1.Config
}

// ProviderConfig lists the providers' config.
type ProviderConfig struct {
	Secrets *secrets.Config
	Enclave *enclave.ProviderConfig
	AWSKMS  *AWSKMSConfig
}

// AWSKMSConfig contains the KMS settings that the host sends to the enclave.
type AWSKMSConfig struct {
	Localstack *AWSKMSLocalstackConfig `json:"localstack" mapstructure:"localstack"`
	Arns       []string                `json:"arns" mapstructure:"arns"`
}

// AWSKMSLocalstackConfig selects LocalStack as the KMS backend.
type AWSKMSLocalstackConfig struct {
	Enabled bool `json:"enabled" mapstructure:"enabled"`
}

func newConfig(
	baseConfig *config.BaseConfig,
	secretsConfig *secrets.Config,
	awsKMSConfig *AWSKMSConfig,
) *Config {
	return &Config{
		BaseConfig: baseConfig,
		Public: &PublicConfig{
			Server: &grpcServer.Config{
				Host: "0.0.0.0",
				Port: 8080,
				// Initialized so APP_PUBLIC_SERVER_TLS_* env overrides bind even
				// when the config file omits the tls block. Disabled by default.
				TLS: &grpcServer.TLSConfig{Enabled: false},
			},
		},
		Profiler: &ProfilerConfig{
			Enabled: false,
		},
		Metrics:   metric.NewConfig(),
		Telemetry: telemetry.NewConfig(),
		Service: &ServiceConfig{
			Signer: signerv1.NewConfig(),
		},
		Provider: &ProviderConfig{
			Secrets: secretsConfig,
			Enclave: enclave.NewProviderConfig(),
			AWSKMS:  awsKMSConfig,
		},
	}
}
