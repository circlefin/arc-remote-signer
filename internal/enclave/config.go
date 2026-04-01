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

// Package enclave provides configuration and server functionality for AWS Nitro Enclave operations.
package enclave

import (
	"github.com/circlefin/arc-remote-signer/internal/common/config"
	grpcServer "github.com/circlefin/arc-remote-signer/internal/common/grpc/server"
)

// Config should implement config.ApplicationConfig.
var _ config.ApplicationConfig = &Config{}

// Config represents the complete enclave configuration.
type Config struct {
	// Base config
	*config.BaseConfig `mapstructure:",squash"`

	// Public provides configuration for the public gRPC server.
	Public *PublicConfig `mapstructure:"public"`

	// NitroEnclave contains config for the Nitro enclave.
	NitroEnclave *NitroEnclaveConfig
}

// PublicConfig wraps server configuration to match YAML structure.
type PublicConfig struct {
	// Server provides gRPC server configuration.
	Server *grpcServer.Config `mapstructure:"server"`
}

// NewConfig creates a new config with sensible defaults.
func NewConfig() *Config {
	return &Config{
		BaseConfig: config.NewBaseConfig(),
		Public: &PublicConfig{
			Server: &grpcServer.Config{
				Host: "127.0.0.1",
				Port: 5000,
			},
		},
		NitroEnclave: &NitroEnclaveConfig{
			Enabled: true,
		},
	}
}

// GetName returns the service name.
func (c *Config) GetName() string {
	return "nitro-enclave-signer-internal"
}

// IsProduction returns true if running in production.
func (c *Config) IsProduction() bool {
	return c.Env == config.Prod
}

// IsDevelopment returns true if running in development.
func (c *Config) IsDevelopment() bool {
	return c.Env == config.Dev
}

// NitroEnclaveConfig contains config for the Nitro enclave.
type NitroEnclaveConfig struct {
	Enabled bool
}
