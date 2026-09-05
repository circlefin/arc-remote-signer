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

// Package awsproxy bridges enclave-internal loopback TCP traffic over
// vsock (production) or TCP (dev/CI) to the parent EC2 instance / host
// gateway. See awsproxy.go for the Linux implementation and
// awsproxy_stub.go for the non-Linux build.
package awsproxy

// DefaultBasePort is the default loopback TCP port the enclave-side proxy
// listens on. Additional AWS services occupy consecutive ports starting at
// BasePort + len(byteproxy.AWSServiceNames) - 1.
const DefaultBasePort uint32 = 10316

// DefaultMaxConns mirrors gateway-tee-signer's socat max-children=50 default
// and bounds the number of concurrent bridged connections per service.
const DefaultMaxConns = 50

// Config configures the enclave-side AWS proxy.
//
// The proxy is mandatory: the enclave always bridges its KMS traffic
// through it — vsock to the parent in production, TCP to the host
// vsockproxy in dev/CI — so there is no on/off toggle.
//
// Construct it via NewConfig(); a zero-value Config is not usable, since
// MaxConns must be > 0 (New rejects MaxConns == 0 via byteproxy.New).
type Config struct {
	// BasePort is the loopback TCP port for the first service. Service i
	// (per byteproxy.AWSServiceNames) binds to BasePort + i.
	BasePort uint32 `mapstructure:"base_port"`

	// MaxConns caps in-flight connections per service.
	MaxConns int `mapstructure:"max_conns"`
}

// NewConfig returns Config defaults suitable for an enclave run.
func NewConfig() *Config {
	return &Config{
		BasePort: DefaultBasePort,
		MaxConns: DefaultMaxConns,
	}
}
