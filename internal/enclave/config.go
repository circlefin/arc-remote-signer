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
	"fmt"

	"github.com/circlefin/arc-remote-signer/internal/common/config"
	grpcServer "github.com/circlefin/arc-remote-signer/internal/common/grpc/server"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awsproxy"
)

// Config should implement config.ApplicationConfig.
var _ config.ApplicationConfig = &Config{}

// Config represents the complete enclave configuration.
type Config struct {
	// Public provides configuration for the public gRPC server.
	Public *PublicConfig `mapstructure:"public"`

	// NitroEnclave contains config for the Nitro enclave.
	NitroEnclave *NitroEnclaveConfig `mapstructure:"nitroEnclave"`

	// Awsproxy contains config for the enclave-side AWS proxy that bridges
	// loopback TCP to the parent (vsock in production, TCP in dev/CI).
	Awsproxy *awsproxy.Config `mapstructure:"awsproxy"`
}

// PublicConfig wraps server configuration to match YAML structure.
type PublicConfig struct {
	// Server provides gRPC server configuration.
	Server *grpcServer.Config `mapstructure:"server"`
}

// NewConfig creates a new config with sensible defaults.
func NewConfig() *Config {
	return &Config{
		Public: &PublicConfig{
			Server: &grpcServer.Config{
				Host: "127.0.0.1",
				Port: 5000,
			},
		},
		NitroEnclave: &NitroEnclaveConfig{
			Enabled:             true,
			AwsproxyEndpoint:    fmt.Sprintf("http://127.0.0.1:%d", awsproxy.DefaultBasePort),
			KmsConnectTimeoutMs: 3000,
		},
		Awsproxy: awsproxy.NewConfig(),
	}
}

// GetName returns the service name.
func (c *Config) GetName() string {
	return "nitro-enclave-signer-internal"
}

// NitroEnclaveConfig contains config for the Nitro enclave.
type NitroEnclaveConfig struct {
	// Enabled controls whether Nitro Enclave features (NSM attestation, vsock) are active.
	Enabled bool `mapstructure:"enabled"`
	// AwsproxyEndpoint is the URL the in-enclave KMS client uses to
	// reach AWS KMS. In both production and dev/CI it points at the
	// enclave-side awsproxy loopback listener (default port 10316, see
	// awsproxy.DefaultBasePort); the proxy then bridges onward — vsock to
	// the parent (real KMS) in production, TCP to the standalone vsockproxy
	// service (which forwards to LocalStack) in dev/CI. See
	// deployments/docker-compose.yaml.
	AwsproxyEndpoint string `mapstructure:"awsproxyEndpoint"`
	// KmsConnectTimeoutMs is the per-request HTTP timeout in milliseconds
	// applied to the in-enclave KMS client. Despite the "Connect" in the
	// name (kept for parity with the host-side awskms.Config.ConnectTimeout
	// field it threads into), it bounds the whole HTTP request — TCP
	// dial, TLS handshake, request, and response — not just the connect
	// phase. Combined with the SDK's default 3 retry attempts and the
	// custom 300 ms MaxBackoff in awskms.go, worst-case total time per
	// Initialize call is roughly 3*timeout + small backoff. Defaults to
	// 3000 ms (3 s).
	KmsConnectTimeoutMs int `mapstructure:"kmsConnectTimeoutMs"`
}
