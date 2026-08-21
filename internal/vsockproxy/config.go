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

// Package vsockproxy is the standalone host-side bridge between vsock
// (production) or TCP (dev/CI) listeners and AWS service endpoints. It
// runs as its own process via the `app run-vsockproxy` subcommand.
package vsockproxy

import (
	"fmt"
)

// configName is the ApplicationConfig.GetName() result; surfaces in
// logging.
const configName = "nitro-enclave-signer-vsockproxy"

// DefaultBasePort is the default vsock port the host-side proxy listens
// on. Additional services occupy consecutive ports (base+1, ...).
const DefaultBasePort uint32 = 10316

// DefaultMaxConns mirrors gateway-tee-signer's socat max-children=50
// default and bounds in-flight connections per service.
const DefaultMaxConns = 50

// endpointTemplates maps each entry in byteproxy.AWSServiceNames to
// the AWS endpoint template used for that service. The "{region}"
// placeholder is substituted with the per-connection region selected by
// the enclave KMS client. Keyed by service name so
// a drift between this map and byteproxy.AWSServiceNames is caught at
// startup.
var endpointTemplates = map[string]string{
	"kms": "kms.{region}.amazonaws.com:443",
}

// EndpointTemplate returns the endpoint template registered for the
// given service. Exported so tests and operators can inspect the
// mapping; New performs the actual {region} substitution and parity
// check at startup.
func EndpointTemplate(service string) (string, error) {
	tmpl, ok := endpointTemplates[service]
	if !ok {
		return "", fmt.Errorf("vsockproxy: no endpoint template registered for service %q", service)
	}
	return tmpl, nil
}

// Config contains the settings for the host-side proxy.
type Config struct {
	Vsockproxy Vsockproxy     `mapstructure:"vsockproxy"`
	Provider   ProviderConfig `mapstructure:"provider"`
}

// Vsockproxy holds the host-side proxy settings.
type Vsockproxy struct {
	// BasePort is the vsock or TCP port for the first service.
	BasePort uint32 `mapstructure:"basePort"`

	// MaxConns caps in-flight connections per service.
	MaxConns int `mapstructure:"maxConns"`
}

// ProviderConfig mirrors the subset of app.Config.Provider that the
// vsockproxy process needs to consume.
type ProviderConfig struct {
	Enclave ProviderEnclaveConfig `mapstructure:"enclave"`
	AWSKMS  ProviderAWSKMSConfig  `mapstructure:"awskms"`
}

// ProviderEnclaveConfig mirrors the subset of the enclave provider
// config that the vsockproxy process needs to consume.
type ProviderEnclaveConfig struct {
	NitroEnclave ProviderNitroEnclaveConfig `mapstructure:"nitroEnclave"`
}

// ProviderNitroEnclaveConfig mirrors the NitroEnclave block from the
// enclave provider config. Only `enabled` is read here; CID/Port belong
// to the app process.
type ProviderNitroEnclaveConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// ProviderAWSKMSConfig contains the KMS settings that the proxy needs.
// ARN regions form the allowlist for standard AWS KMS routes.
type ProviderAWSKMSConfig struct {
	Localstack ProviderAWSKMSLocalstackConfig `mapstructure:"localstack"`
	Arns       []string                       `mapstructure:"arns"`
}

// ProviderAWSKMSLocalstackConfig selects LocalStack as the KMS backend.
type ProviderAWSKMSLocalstackConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// NewConfig returns Config defaults suitable for a host run.
func NewConfig() *Config {
	return &Config{
		Vsockproxy: Vsockproxy{
			BasePort: DefaultBasePort,
			MaxConns: DefaultMaxConns,
		},
	}
}

// GetName implements config.ApplicationConfig so LoadConfig can target
// this Config.
func (c *Config) GetName() string { return configName }
