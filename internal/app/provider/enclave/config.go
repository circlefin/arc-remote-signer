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
	"time"

	"github.com/circlefin/arc-remote-signer/internal/common/grpc/client"
)

const providerName = "enclave"

// enclaveDefaultURL is the default dev URL for the enclave.
const enclaveDefaultURL = "localhost:10350"

// enclaveDefaultCID is the development default. The production policy pins it.
const enclaveDefaultCID = 16

const (
	defaultSignMessageTimeoutMS = 500
	defaultStartupTimeoutMS     = 30000
)

// ProviderConfig contains configuration for the enclave gRPC provider.
type ProviderConfig struct {
	NitroEnclave     *NitroEnclave  `json:"nitroEnclave" mapstructure:"nitroEnclave"`
	Client           *client.Config `json:"client" mapstructure:"client"`
	StartupTimeoutMS int            `json:"startupTimeoutMS" mapstructure:"startupTimeoutMS"`
}

// NitroEnclave contains config for the Nitro Enclave.
type NitroEnclave struct {
	Enabled bool
	// CID is the context ID of the enclave.
	CID uint32
	// Port is the VSOCK port the enclave listens on.
	Port uint32
}

// DefaultMethodTimeouts returns default method timeouts for enclave client RPCs.
func DefaultMethodTimeouts() map[string]client.MethodConfig {
	return map[string]client.MethodConfig{
		"initialize": {
			TimeoutMS:   defaultStartupTimeoutMS,
			MaxAttempts: 1,
		},
		"generatekey": {
			TimeoutMS:   defaultStartupTimeoutMS,
			MaxAttempts: 1,
		},
		"getpublickey": {
			TimeoutMS: defaultStartupTimeoutMS,
		},
		"signmessage": {
			TimeoutMS:   defaultSignMessageTimeoutMS,
			MaxAttempts: 1,
		},
	}
}

// StartupTimeout returns the total budget for host-side enclave initialization.
func (c *ProviderConfig) StartupTimeout() time.Duration {
	if c != nil && c.StartupTimeoutMS > 0 {
		return time.Duration(c.StartupTimeoutMS) * time.Millisecond
	}
	return time.Duration(defaultStartupTimeoutMS) * time.Millisecond
}

// NewProviderConfig provides a new provider config with defaults.
func NewProviderConfig() *ProviderConfig {
	cfg := client.NewClientConfig(providerName, enclaveDefaultURL)
	cfg.RequestTimeoutMS = defaultSignMessageTimeoutMS
	cfg.Methods = DefaultMethodTimeouts()
	return &ProviderConfig{
		NitroEnclave: &NitroEnclave{
			Enabled: false,
			CID:     enclaveDefaultCID,
			Port:    10350,
		},
		Client:           cfg,
		StartupTimeoutMS: defaultStartupTimeoutMS,
	}
}
