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

package enclave

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()

	require.NotNil(t, cfg)
	require.NotNil(t, cfg.Public)
	require.NotNil(t, cfg.Public.Server)
	require.NotNil(t, cfg.NitroEnclave)

	// Check public server defaults
	assert.Equal(t, "127.0.0.1", cfg.Public.Server.Host)
	assert.Equal(t, 5000, cfg.Public.Server.Port)

	// Check nitro enclave defaults
	assert.True(t, cfg.NitroEnclave.Enabled)
}

func TestConfigHasNoDeploymentEnvironment(t *testing.T) {
	_, found := reflect.TypeOf(Config{}).FieldByName("Env")
	require.False(t, found, "enclave config must not accept APP_ENV")
}

func TestConfig_GetName(t *testing.T) {
	cfg := NewConfig()
	assert.Equal(t, "nitro-enclave-signer-internal", cfg.GetName())
}

func TestConfig_ImplementsApplicationConfig(t *testing.T) {
	cfg := NewConfig()
	var _ config.ApplicationConfig = cfg
	assert.Equal(t, "nitro-enclave-signer-internal", cfg.GetName())
}

func TestPublicConfig_Structure(t *testing.T) {
	cfg := NewConfig()

	assert.NotNil(t, cfg.Public)
	assert.NotNil(t, cfg.Public.Server)
	assert.Equal(t, "127.0.0.1", cfg.Public.Server.Host)
	assert.Equal(t, 5000, cfg.Public.Server.Port)
}

func TestNitroEnclaveConfig_Defaults(t *testing.T) {
	cfg := NewConfig()

	assert.NotNil(t, cfg.NitroEnclave)
	assert.True(t, cfg.NitroEnclave.Enabled)
}

func TestNitroEnclaveConfig_Disabled(t *testing.T) {
	cfg := NewConfig()
	cfg.NitroEnclave.Enabled = false

	assert.False(t, cfg.NitroEnclave.Enabled)
}

// TestLoadConfig_YamlOverridesMutatedDefaults guards against a
// mapstructure tag drift bug: if a tag does not match the key that
// yaml.Marshal of the defaults produces (lowercased Go field name with
// no separator), the YAML subtree is silently dropped and NewConfig
// defaults take over. We detect that by mutating the defaults before
// LoadConfig and verifying the YAML value wins.
func TestLoadConfig_YamlOverridesMutatedDefaults(t *testing.T) {
	yamlPath := filepath.Join(t.TempDir(), "enclave.yaml")
	const yamlBody = `public:
  server:
    host: 1.2.3.4
    port: 11111
nitroEnclave:
  enabled: false
  awsproxyEndpoint: http://example:8080
  kmsConnectTimeoutMs: 4242
`
	require.NoError(t, os.WriteFile(yamlPath, []byte(yamlBody), 0o600))

	cfg := NewConfig()
	cfg.Public.Server.Host = "DEFAULT-HOST"
	cfg.Public.Server.Port = 99999
	cfg.NitroEnclave.Enabled = true
	cfg.NitroEnclave.AwsproxyEndpoint = "DEFAULT-ENDPOINT"
	cfg.NitroEnclave.KmsConnectTimeoutMs = 99999

	config.LoadConfig(cfg, yamlPath)

	assert.Equal(t, "1.2.3.4", cfg.Public.Server.Host)
	assert.Equal(t, 11111, cfg.Public.Server.Port)
	assert.False(t, cfg.NitroEnclave.Enabled,
		"YAML nitroEnclave.enabled=false must override mutated default Enabled=true")
	assert.Equal(t, "http://example:8080", cfg.NitroEnclave.AwsproxyEndpoint,
		"YAML nitroEnclave.awsproxyEndpoint must override mutated default")
	assert.Equal(t, 4242, cfg.NitroEnclave.KmsConnectTimeoutMs,
		"YAML nitroEnclave.kmsConnectTimeoutMs must override mutated default")
}

// TestLoadConfig_EnvOverridesYaml pins the env-var override path used by
// docker-compose to point the in-enclave KMS client at LocalStack in dev
// mode. The docker-compose file sets APP_NITROENCLAVE_AWSPROXYENDPOINT,
// expecting it to flow through viper's env replacer into
// NitroEnclaveConfig.AwsproxyEndpoint. If the mapstructure tag spelling
// or viper key normalisation drifts, this test fails fast so dev runs
// don't silently fall back to the production default.
func TestLoadConfig_EnvOverridesYaml(t *testing.T) {
	yamlPath := filepath.Join(t.TempDir(), "enclave.yaml")
	const yamlBody = `nitroEnclave:
  enabled: true
  awsproxyEndpoint: http://yaml-default:10316
`
	require.NoError(t, os.WriteFile(yamlPath, []byte(yamlBody), 0o600))

	t.Setenv("APP_NITROENCLAVE_AWSPROXYENDPOINT", "http://localstack:4566")

	cfg := NewConfig()
	config.LoadConfig(cfg, yamlPath)

	assert.Equal(t, "http://localstack:4566", cfg.NitroEnclave.AwsproxyEndpoint,
		"APP_NITROENCLAVE_AWSPROXYENDPOINT must override YAML and default value")
}

func TestValidateAwsproxyConfig(t *testing.T) {
	t.Run("matching default ports pass", func(t *testing.T) {
		require.NoError(t, validateAwsproxyConfig(NewConfig()))
	})

	t.Run("port mismatch is rejected", func(t *testing.T) {
		cfg := NewConfig()
		cfg.Awsproxy.BasePort = cfg.Awsproxy.BasePort + 1 // diverge from the endpoint port
		err := validateAwsproxyConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config mismatch")
	})

	t.Run("localhost host is accepted", func(t *testing.T) {
		cfg := NewConfig()
		cfg.NitroEnclave.AwsproxyEndpoint = fmt.Sprintf("http://localhost:%d", cfg.Awsproxy.BasePort)
		require.NoError(t, validateAwsproxyConfig(cfg))
	})

	t.Run("non-loopback host is rejected", func(t *testing.T) {
		cfg := NewConfig()
		cfg.NitroEnclave.AwsproxyEndpoint = fmt.Sprintf("http://evil.example:%d", cfg.Awsproxy.BasePort)
		err := validateAwsproxyConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "loopback")
	})

	t.Run("endpoint without a port is rejected", func(t *testing.T) {
		cfg := NewConfig()
		cfg.NitroEnclave.AwsproxyEndpoint = "http://127.0.0.1"
		err := validateAwsproxyConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "has no port")
	})

	t.Run("malformed endpoint is rejected", func(t *testing.T) {
		cfg := NewConfig()
		cfg.NitroEnclave.AwsproxyEndpoint = "://bad"
		err := validateAwsproxyConfig(cfg)
		require.Error(t, err)
	})
}

func TestConfig_CustomValues(t *testing.T) {
	cfg := NewConfig()

	// Modify config
	cfg.Public.Server.Host = "0.0.0.0"
	cfg.Public.Server.Port = 8080
	cfg.NitroEnclave.Enabled = false

	// Verify modifications
	assert.Equal(t, "0.0.0.0", cfg.Public.Server.Host)
	assert.Equal(t, 8080, cfg.Public.Server.Port)
	assert.False(t, cfg.NitroEnclave.Enabled)
}
