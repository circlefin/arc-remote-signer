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

//go:build prod

package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	awsSdkConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/circlefin/arc-remote-signer/internal/common/config"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/stretchr/testify/require"
)

func TestApplyBuildPolicy_ReappliesAfterEnvironmentLoad(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	t.Setenv("APP_PROVIDER_ENCLAVE_NITROENCLAVE_ENABLED", "false")
	t.Setenv("APP_PROVIDER_ENCLAVE_NITROENCLAVE_CID", "1")
	t.Setenv("APP_PROVIDER_ENCLAVE_NITROENCLAVE_PORT", "1")
	t.Setenv("APP_PROVIDER_ENCLAVE_CLIENT_BASEURL", "127.0.0.1:1")
	t.Setenv("APP_PROVIDER_SECRETS_LOCALSTACK_ENABLED", "true")
	t.Setenv("APP_PROVIDER_AWSKMS_LOCALSTACK_ENABLED", "true")

	configFile := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(configFile, []byte("{}\n"), 0o600))

	cfg := NewConfig()
	config.LoadConfig(cfg, configFile)

	require.Equal(t, config.Dev, cfg.Env)
	require.False(t, cfg.Provider.Enclave.NitroEnclave.Enabled)
	require.Equal(t, uint32(1), cfg.Provider.Enclave.NitroEnclave.CID)
	require.Equal(t, uint32(1), cfg.Provider.Enclave.NitroEnclave.Port)
	require.Equal(t, "127.0.0.1:1", cfg.Provider.Enclave.Client.BaseURL)
	require.True(t, cfg.Provider.Secrets.Localstack.Enabled)
	require.True(t, cfg.Provider.AWSKMS.Localstack.Enabled)

	applyBuildPolicy(cfg)

	require.Equal(t, config.Prod, cfg.Env)
	require.True(t, cfg.Provider.Enclave.NitroEnclave.Enabled)
	require.Equal(t, uint32(16), cfg.Provider.Enclave.NitroEnclave.CID)
	require.Equal(t, uint32(10350), cfg.Provider.Enclave.NitroEnclave.Port)
	require.Equal(t, "localhost:10350", cfg.Provider.Enclave.Client.BaseURL)
	require.False(t, cfg.Provider.Secrets.Localstack.Enabled)
	require.False(t, cfg.Provider.AWSKMS.Localstack.Enabled)
}

func TestApplyBuildPolicy_PreservesStagingLabelAndEnforcesPolicy(t *testing.T) {
	cfg := NewConfig()
	cfg.Env = config.Stg
	cfg.Provider.Enclave.NitroEnclave.Enabled = false
	cfg.Provider.Enclave.NitroEnclave.CID = 1
	cfg.Provider.Enclave.NitroEnclave.Port = 1
	cfg.Provider.Enclave.Client.BaseURL = "127.0.0.1:1"
	cfg.Provider.Secrets.Localstack.Enabled = true
	cfg.Provider.AWSKMS.Localstack.Enabled = true

	applyBuildPolicy(cfg)

	require.Equal(t, config.Stg, cfg.Env)
	require.True(t, cfg.Provider.Enclave.NitroEnclave.Enabled)
	require.Equal(t, productionEnclaveCID, cfg.Provider.Enclave.NitroEnclave.CID)
	require.Equal(t, productionEnclavePort, cfg.Provider.Enclave.NitroEnclave.Port)
	require.Equal(t, "localhost:10350", cfg.Provider.Enclave.Client.BaseURL)
	require.False(t, cfg.Provider.Secrets.Localstack.Enabled)
	require.False(t, cfg.Provider.AWSKMS.Localstack.Enabled)
}

func TestProductionConfig_PreservesEnclaveRequestTimeout(t *testing.T) {
	cfg := NewConfig()
	config.LoadConfig(cfg, filepath.Join("..", "..", "configs", "app.production.yaml"))

	require.Equal(t, 500, cfg.Provider.Enclave.Client.RequestTimeoutMS)
}

func TestNewConfig_ExcludesDevelopmentDefaults(t *testing.T) {
	cfg := NewConfig()

	require.Equal(t, config.Prod, cfg.Env)
	require.True(t, cfg.Provider.Enclave.NitroEnclave.Enabled)
	require.Empty(t, cfg.Provider.Secrets.Localstack.Endpoint)
	require.Empty(t, cfg.Provider.Secrets.Localstack.Region)
	require.False(t, cfg.Provider.Secrets.Localstack.Enabled)
	require.Empty(t, cfg.Provider.AWSKMS.Arns)
	require.False(t, cfg.Provider.AWSKMS.Localstack.Enabled)
}

func TestNewRuntimeEnclave_CreatesNitroClient(t *testing.T) {
	client, conn, err := newRuntimeEnclave(NewConfig().Provider.Enclave)
	require.NoError(t, err)
	require.NotNil(t, client)
	require.NotNil(t, conn)
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close enclave connection: %v", err)
		}
	})
}

func TestLoadRuntimeAWSConfig_IgnoresEndpointOverrides(t *testing.T) {
	t.Run("environment", func(t *testing.T) {
		t.Setenv("AWS_REGION", "us-east-1")
		t.Setenv("AWS_ENDPOINT_URL", "http://localhost:4566")
		t.Setenv("AWS_ENDPOINT_URL_SECRETS_MANAGER", "http://localhost:4567")
		t.Setenv("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "false")

		assertProductionIgnoresEndpoint(t, "http://localhost:4567")
	})

	t.Run("shared configuration", func(t *testing.T) {
		configFile := filepath.Join(t.TempDir(), "config")
		require.NoError(t, os.WriteFile(configFile, []byte(`[profile production]
region = us-east-1
endpoint_url = http://localhost:4568
services = production-services

[services production-services]
secrets_manager =
  endpoint_url = http://localhost:4569
`), 0o600))
		t.Setenv("AWS_CONFIG_FILE", configFile)
		t.Setenv("AWS_PROFILE", "production")
		t.Setenv("AWS_SDK_LOAD_CONFIG", "1")
		t.Setenv("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "false")

		assertProductionIgnoresEndpoint(t, "http://localhost:4569")
	})
}

func assertProductionIgnoresEndpoint(t *testing.T, unsafeEndpoint string) {
	t.Helper()
	ctx := context.Background()

	unsafeConfig, err := awsSdkConfig.LoadDefaultConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, unsafeEndpoint, *secretsmanager.NewFromConfig(unsafeConfig).Options().BaseEndpoint)

	safeConfig, err := loadRuntimeAWSConfig(ctx, NewConfig(), logging.Get("production-config-test"))
	require.NoError(t, err)
	require.Nil(t, safeConfig.BaseEndpoint)
	require.Nil(t, secretsmanager.NewFromConfig(safeConfig).Options().BaseEndpoint)
}
