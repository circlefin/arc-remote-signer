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
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()

	require.NotNil(t, cfg)
	require.NotNil(t, cfg.BaseConfig)
	require.NotNil(t, cfg.Public)
	require.NotNil(t, cfg.Public.Server)
	require.NotNil(t, cfg.NitroEnclave)

	// Check base config defaults
	assert.Equal(t, config.Dev, cfg.Env)

	// Check public server defaults
	assert.Equal(t, "127.0.0.1", cfg.Public.Server.Host)
	assert.Equal(t, 5000, cfg.Public.Server.Port)

	// Check nitro enclave defaults
	assert.True(t, cfg.NitroEnclave.Enabled)
}

func TestConfig_GetName(t *testing.T) {
	cfg := NewConfig()
	assert.Equal(t, "nitro-enclave-signer-internal", cfg.GetName())
}

func TestConfig_IsProduction(t *testing.T) {
	tests := []struct {
		name     string
		env      config.Environment
		expected bool
	}{
		{
			name:     "Dev environment is not production",
			env:      config.Dev,
			expected: false,
		},
		{
			name:     "QA environment is not production",
			env:      config.QA,
			expected: false,
		},
		{
			name:     "Stg environment is not production",
			env:      config.Stg,
			expected: false,
		},
		{
			name:     "Prod environment is production",
			env:      config.Prod,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Env = tt.env
			assert.Equal(t, tt.expected, cfg.IsProduction())
		})
	}
}

func TestConfig_IsDevelopment(t *testing.T) {
	tests := []struct {
		name     string
		env      config.Environment
		expected bool
	}{
		{
			name:     "Dev environment is development",
			env:      config.Dev,
			expected: true,
		},
		{
			name:     "QA environment is not development",
			env:      config.QA,
			expected: false,
		},
		{
			name:     "Stg environment is not development",
			env:      config.Stg,
			expected: false,
		},
		{
			name:     "Prod environment is not development",
			env:      config.Prod,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Env = tt.env
			assert.Equal(t, tt.expected, cfg.IsDevelopment())
		})
	}
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

func TestConfig_CustomValues(t *testing.T) {
	cfg := NewConfig()

	// Modify config
	cfg.Env = config.Prod
	cfg.Public.Server.Host = "0.0.0.0"
	cfg.Public.Server.Port = 8080
	cfg.NitroEnclave.Enabled = false

	// Verify modifications
	assert.Equal(t, config.Prod, cfg.Env)
	assert.Equal(t, "0.0.0.0", cfg.Public.Server.Host)
	assert.Equal(t, 8080, cfg.Public.Server.Port)
	assert.False(t, cfg.NitroEnclave.Enabled)
	assert.True(t, cfg.IsProduction())
	assert.False(t, cfg.IsDevelopment())
}
