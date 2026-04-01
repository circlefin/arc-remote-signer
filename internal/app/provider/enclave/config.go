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
	"github.com/circlefin/arc-remote-signer/internal/common/grpc/client"
)

const providerName = "enclave"

// enclaveDefaultURL is the default dev URL for the enclave.
const enclaveDefaultURL = "localhost:10350"

// enclaveDefaultCID is the default CID for the enclave.
// https://github.com/circlefin/arc-remote-signer/blob/master/docker/run.sh#L6
const enclaveDefaultCID = 16

// ProviderConfig contains configuration for the enclave gRPC provider.
type ProviderConfig struct {
	NitroEnclave *NitroEnclave
	Client       *client.Config
}

// NitroEnclave contains config for the Nitro Enclave.
type NitroEnclave struct {
	Enabled bool
	// CID is the context ID of the enclave (typically 16 for first enclave).
	CID uint32
	// Port is the VSOCK port the enclave listens on.
	Port uint32
}

// NewProviderConfig provides a new provider config with defaults.
func NewProviderConfig() *ProviderConfig {
	cfg := client.NewClientConfig(providerName, enclaveDefaultURL)
	return &ProviderConfig{
		NitroEnclave: &NitroEnclave{
			Enabled: false,
			CID:     enclaveDefaultCID,
			Port:    10350,
		},
		Client: cfg,
	}
}
