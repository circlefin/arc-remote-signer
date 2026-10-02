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

//go:build linux && !prod

package vsockproxy

import (
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
	"github.com/stretchr/testify/require"
)

// TestTransportOptionForConfig verifies that the helper used by Run
// picks WithVsockTransport when provider.enclave.nitroEnclave.enabled is
// true and WithTCPTransport() otherwise. This is the small piece of
// logic inside Run that we test in isolation; the full Run path is
// covered by the docker-compose integration test.
func TestTransportOptionForConfig(t *testing.T) {
	t.Run("VsockWhenNitroEnabled", func(t *testing.T) {
		cfg := &Config{
			Provider: ProviderConfig{
				Enclave: ProviderEnclaveConfig{
					NitroEnclave: ProviderNitroEnclaveConfig{Enabled: true},
				},
			},
		}
		opt := transportOptionForConfig(cfg)
		require.NotNil(t, opt)
		o := options{}
		opt(&o)
		require.Equal(t, byteproxy.TransportVsock, o.transport)
	})

	t.Run("TCPWhenNitroDisabled", func(t *testing.T) {
		cfg := &Config{
			Provider: ProviderConfig{
				Enclave: ProviderEnclaveConfig{
					NitroEnclave: ProviderNitroEnclaveConfig{Enabled: false},
				},
			},
		}
		opt := transportOptionForConfig(cfg)
		require.NotNil(t, opt)
		o := options{}
		opt(&o)
		require.Equal(t, byteproxy.TransportTCP, o.transport)
	})
}

// TestRun_NewFailureReturnsError verifies that Run surfaces the New
// error directly (no log.Fatal). The config selects vsock mode but
// supplies no ARN, so route allowlist construction fails before any port is bound.
func TestRun_NewFailureReturnsError(t *testing.T) {
	cfg := &Config{
		Vsockproxy: Vsockproxy{
			BasePort: 30000,
			MaxConns: 4,
		},
		Provider: ProviderConfig{
			Enclave: ProviderEnclaveConfig{
				NitroEnclave: ProviderNitroEnclaveConfig{Enabled: true},
			},
		},
	}

	err := Run(cfg)
	require.Error(t, err)
}
