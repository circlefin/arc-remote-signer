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
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/circlefin/arc-remote-signer/internal/app/provider/secrets"
	"github.com/circlefin/arc-remote-signer/internal/common/config"
	"github.com/stretchr/testify/require"
)

func TestParseAwsConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     *Config
		wantRegion string
		wantError  bool
	}{
		{
			name: "default config",
			config: &Config{
				Provider: &ProviderConfig{
					Secrets: secrets.NewConfig(),
				},
			},
			wantRegion: "",
			wantError:  false,
		},
		{
			name: "with region",
			config: &Config{
				Provider: &ProviderConfig{
					Secrets: &secrets.Config{
						Localstack: &secrets.LocalstackConfig{
							Region: "us-west-2",
						},
					},
				},
			},
			wantRegion: "us-west-2",
			wantError:  false,
		},
		{
			name: "with endpoint",
			config: &Config{
				Provider: &ProviderConfig{
					Secrets: &secrets.Config{
						Localstack: &secrets.LocalstackConfig{
							Endpoint: "http://localhost:4566",
						},
					},
				},
			},
			wantRegion: "",
			wantError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			awsConfig, err := MergeAwsConfigWithLocalstack(tt.config)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, awsConfig)
			if tt.wantRegion != "" {
				require.Equal(t, tt.wantRegion, awsConfig.Region)
			}
		})
	}
}

func TestRetrieveAWSConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     *Config
		wantError  bool
		wantConfig aws.Config
	}{
		{
			name: "standard aws config with nil secrets",
			config: &Config{
				BaseConfig: config.NewBaseConfig(),
				Provider: &ProviderConfig{
					Secrets: nil,
				},
			},
			wantError: true,
		},
		{
			name: "standard aws config with nil localstack",
			config: &Config{
				BaseConfig: config.NewBaseConfig(),
				Provider: &ProviderConfig{
					Secrets: &secrets.Config{
						Localstack: nil,
					},
				},
			},
			wantError: true,
		},
		{
			name: "standard aws config with localstack disabled",
			config: &Config{
				BaseConfig: config.NewBaseConfig(),
				Provider: &ProviderConfig{
					Secrets: &secrets.Config{
						Localstack: &secrets.LocalstackConfig{
							Enabled:  false,
							Endpoint: "",
						},
					},
				},
			},
			wantError: false,
		},
		{
			name: "localstack config with endpoint",
			config: &Config{
				BaseConfig: config.NewBaseConfig(),
				Provider: &ProviderConfig{
					Secrets: &secrets.Config{
						Localstack: &secrets.LocalstackConfig{
							Enabled:  true,
							Endpoint: "http://localhost:4566",
						},
					},
				},
			},
			wantError: false,
		},
	}

	logger := getLogger()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			awsConfig, err := retrieveAWSConfig(context.Background(), tt.config, logger)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, awsConfig)
		})
	}
}

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()

	require.NotNil(t, cfg)
	require.NotNil(t, cfg.BaseConfig)
	require.NotNil(t, cfg.Public)
	require.NotNil(t, cfg.Public.Server)
	require.NotNil(t, cfg.Profiler)
	require.NotNil(t, cfg.Metrics)
	require.NotNil(t, cfg.Telemetry)
	require.NotNil(t, cfg.Service)
	require.NotNil(t, cfg.Service.Signer)
	require.NotNil(t, cfg.Provider)
	require.NotNil(t, cfg.Provider.Secrets)
	require.NotNil(t, cfg.Provider.Enclave)
	require.NotNil(t, cfg.Provider.AWSKMS)

	// Check base config defaults
	require.Equal(t, config.Dev, cfg.Env)

	// Check public server defaults
	require.Equal(t, "0.0.0.0", cfg.Public.Server.Host)
	require.Equal(t, 8080, cfg.Public.Server.Port)

	// Check profiler defaults
	require.False(t, cfg.Profiler.Enabled)
}

func TestNewConfig_TLSDefaultEnablesEnvBinding(t *testing.T) {
	cfg := NewConfig()

	// TLS must be materialized (non-nil) so the loader registers the
	// public.server.tls.* keys and APP_PUBLIC_SERVER_TLS_* env vars can bind.
	require.NotNil(t, cfg.Public.Server.TLS)
	require.False(t, cfg.Public.Server.TLS.Enabled)
}

func TestLoadConfig_TLSEnvOverride(t *testing.T) {
	t.Setenv("APP_PUBLIC_SERVER_TLS_ENABLED", "true")
	t.Setenv("APP_PUBLIC_SERVER_TLS_CERT", "/etc/tls/server.crt")
	t.Setenv("APP_PUBLIC_SERVER_TLS_KEY", "/etc/tls/server.key")

	cfg := NewConfig()
	config.LoadConfig(cfg, "")

	require.NotNil(t, cfg.Public.Server.TLS)
	require.True(t, cfg.Public.Server.TLS.Enabled)
	require.Equal(t, "/etc/tls/server.crt", cfg.Public.Server.TLS.Cert)
	require.Equal(t, "/etc/tls/server.key", cfg.Public.Server.TLS.Key)
}

func TestConfig_GetName(t *testing.T) {
	cfg := NewConfig()
	require.Equal(t, "nitro-enclave-signer", cfg.GetName())
}

func TestConfig_ImplementsApplicationConfig(t *testing.T) {
	cfg := NewConfig()
	var _ config.ApplicationConfig = cfg
	require.Equal(t, "nitro-enclave-signer", cfg.GetName())
}

func TestPublicConfig_Structure(t *testing.T) {
	cfg := NewConfig()

	require.NotNil(t, cfg.Public)
	require.NotNil(t, cfg.Public.Server)
	require.Equal(t, "0.0.0.0", cfg.Public.Server.Host)
	require.Equal(t, 8080, cfg.Public.Server.Port)
}

func TestProfilerConfig_Defaults(t *testing.T) {
	cfg := NewConfig()

	require.NotNil(t, cfg.Profiler)
	require.False(t, cfg.Profiler.Enabled)
}

func TestProfilerConfig_Enabled(t *testing.T) {
	cfg := NewConfig()
	cfg.Profiler.Enabled = true

	require.True(t, cfg.Profiler.Enabled)
}

func TestServiceConfig_Structure(t *testing.T) {
	cfg := NewConfig()

	require.NotNil(t, cfg.Service)
	require.NotNil(t, cfg.Service.Signer)
}

func TestProviderConfig_Structure(t *testing.T) {
	cfg := NewConfig()

	require.NotNil(t, cfg.Provider)
	require.NotNil(t, cfg.Provider.Secrets)
	require.NotNil(t, cfg.Provider.Enclave)
	require.NotNil(t, cfg.Provider.AWSKMS)
}

func TestMergeAwsConfigWithLocalstack_Comprehensive(t *testing.T) {
	tests := []struct {
		name       string
		endpoint   string
		region     string
		wantRegion string
	}{
		{
			name:       "with endpoint and region",
			endpoint:   "http://localhost:4566",
			region:     "us-east-1",
			wantRegion: "us-east-1",
		},
		{
			name:       "with region only",
			endpoint:   "",
			region:     "us-west-2",
			wantRegion: "us-west-2",
		},
		{
			name:       "with endpoint only",
			endpoint:   "http://localhost:4566",
			region:     "",
			wantRegion: "",
		},
		{
			name:       "without endpoint and region",
			endpoint:   "",
			region:     "",
			wantRegion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Provider.Secrets.Localstack.Endpoint = tt.endpoint
			cfg.Provider.Secrets.Localstack.Region = tt.region

			awsConfig, err := MergeAwsConfigWithLocalstack(cfg)

			require.NoError(t, err)
			require.NotNil(t, awsConfig)
			if tt.wantRegion != "" {
				require.Equal(t, tt.wantRegion, awsConfig.Region)
			}
		})
	}
}

func TestRetrieveAWSConfig_ErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func() *Config
		wantError   string
	}{
		{
			name: "nil base config",
			setupConfig: func() *Config {
				cfg := NewConfig()
				cfg.BaseConfig = nil
				return cfg
			},
			wantError: "secrets config unavailable",
		},
		{
			name: "nil secrets config",
			setupConfig: func() *Config {
				cfg := NewConfig()
				cfg.Provider.Secrets = nil
				return cfg
			},
			wantError: "secrets config unavailable",
		},
		{
			name: "nil localstack config",
			setupConfig: func() *Config {
				cfg := NewConfig()
				cfg.Provider.Secrets.Localstack = nil
				return cfg
			},
			wantError: "secrets config unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.setupConfig()
			_, err := retrieveAWSConfig(context.Background(), cfg, getLogger())
			require.Error(t, err)
			require.EqualError(t, err, tt.wantError)
		})
	}
}

func TestRetrieveAWSConfig_EnvironmentBehavior(t *testing.T) {
	tests := []struct {
		name               string
		env                config.Environment
		localstackEnabled  bool
		localstackEndpoint string
		expectLocalstack   bool
	}{
		{
			name:               "dev with localstack enabled and endpoint",
			env:                config.Dev,
			localstackEnabled:  true,
			localstackEndpoint: "http://localhost:4566",
			expectLocalstack:   true,
		},
		{
			name:               "qa with localstack enabled and endpoint",
			env:                config.QA,
			localstackEnabled:  true,
			localstackEndpoint: "http://localhost:4566",
			expectLocalstack:   true,
		},
		{
			name:               "stg with localstack (should use standard aws)",
			env:                config.Stg,
			localstackEnabled:  true,
			localstackEndpoint: "http://localhost:4566",
			expectLocalstack:   false,
		},
		{
			name:               "prod with localstack (should use standard aws)",
			env:                config.Prod,
			localstackEnabled:  true,
			localstackEndpoint: "http://localhost:4566",
			expectLocalstack:   false,
		},
		{
			name:               "dev with localstack disabled",
			env:                config.Dev,
			localstackEnabled:  false,
			localstackEndpoint: "http://localhost:4566",
			expectLocalstack:   false,
		},
		{
			name:               "dev with localstack enabled but no endpoint",
			env:                config.Dev,
			localstackEnabled:  true,
			localstackEndpoint: "",
			expectLocalstack:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Env = tt.env
			cfg.Provider.Secrets.Localstack.Enabled = tt.localstackEnabled
			cfg.Provider.Secrets.Localstack.Endpoint = tt.localstackEndpoint
			if tt.expectLocalstack {
				cfg.Provider.Secrets.Localstack.Region = "us-east-1"
			}

			awsConfig, err := retrieveAWSConfig(context.Background(), cfg, getLogger())

			require.NoError(t, err)
			require.NotNil(t, awsConfig)

			if tt.expectLocalstack {
				require.Equal(t, "us-east-1", awsConfig.Region)
			}
		})
	}
}

func TestConfig_CustomValues(t *testing.T) {
	cfg := NewConfig()

	// Modify config
	cfg.Env = config.Stg
	cfg.Public.Server.Host = "192.168.1.1"
	cfg.Public.Server.Port = 9090
	cfg.Profiler.Enabled = true

	// Verify modifications
	require.Equal(t, config.Stg, cfg.Env)
	require.Equal(t, "192.168.1.1", cfg.Public.Server.Host)
	require.Equal(t, 9090, cfg.Public.Server.Port)
	require.True(t, cfg.Profiler.Enabled)
}
