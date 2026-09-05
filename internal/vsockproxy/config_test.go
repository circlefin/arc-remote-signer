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

package vsockproxy

import (
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/config"
	"github.com/stretchr/testify/require"
)

func TestNewConfig_Defaults(t *testing.T) {
	cfg := NewConfig()

	require.NotNil(t, cfg)
	require.Equal(t, DefaultBasePort, cfg.Vsockproxy.BasePort)
	require.Equal(t, DefaultMaxConns, cfg.Vsockproxy.MaxConns)
	require.False(t, cfg.Provider.Enclave.NitroEnclave.Enabled,
		"nitroEnclave.enabled default must mirror the app provider default (false)")
	require.Empty(t, cfg.Provider.AWSKMS.Arns,
		"awskms.arns default must be empty so callers supply a real list")

	require.Equal(t, uint32(10316), DefaultBasePort,
		"DefaultBasePort must match gateway-tee-signer's aws_proxy_port default")
	require.Equal(t, 50, DefaultMaxConns,
		"DefaultMaxConns must match gateway-tee-signer's socat max-children=50")
}

func TestConfig_GetName(t *testing.T) {
	cfg := NewConfig()
	require.Equal(t, "nitro-enclave-signer-vsockproxy", cfg.GetName())
}

// TestLoadConfig_EnvOverridesYaml pins the APP_VSOCKPROXY_* viper path
// production deployments depend on: every override goes through
// config.LoadConfig, which merges defaults + app.yaml + env in that
// order. A regression in the mapstructure tags, EnvKeyReplacer, or
// the Vsockproxy struct shape would silently leave compose / prod on
// stale values without this assertion firing.
func TestLoadConfig_EnvOverridesYaml(t *testing.T) {
	t.Setenv("APP_VSOCKPROXY_BASEPORT", "20000")
	t.Setenv("APP_VSOCKPROXY_MAXCONNS", "100")
	t.Setenv("APP_PROVIDER_ENCLAVE_NITROENCLAVE_ENABLED", "true")
	t.Setenv("APP_PROVIDER_AWSKMS_LOCALSTACK_ENABLED", "true")

	cfg := NewConfig()
	config.LoadConfig(cfg, "../../configs/app.yaml")

	require.Equal(t, uint32(20000), cfg.Vsockproxy.BasePort)
	require.Equal(t, 100, cfg.Vsockproxy.MaxConns)
	require.True(t, cfg.Provider.Enclave.NitroEnclave.Enabled,
		"APP_PROVIDER_ENCLAVE_NITROENCLAVE_ENABLED must drive the transport selector in run.go")
	require.True(t, cfg.Provider.AWSKMS.Localstack.Enabled)
}

func TestEndpointTemplate(t *testing.T) {
	t.Run("KnownService", func(t *testing.T) {
		tmpl, err := EndpointTemplate("kms")
		require.NoError(t, err)
		require.Contains(t, tmpl, "{region}")
		require.Contains(t, tmpl, "kms.")
		require.Contains(t, tmpl, ":443")
	})

	t.Run("UnknownService", func(t *testing.T) {
		_, err := EndpointTemplate("nonexistent-service")
		require.Error(t, err)
		require.Contains(t, err.Error(), "nonexistent-service")
	})
}
