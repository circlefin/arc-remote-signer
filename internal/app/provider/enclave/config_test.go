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
	"time"

	grpcClient "github.com/circlefin/arc-remote-signer/internal/common/grpc/client"
	"github.com/stretchr/testify/require"
)

func TestNewProviderConfig_Defaults(t *testing.T) {
	cfg := NewProviderConfig()

	require.NotNil(t, cfg)
	require.NotNil(t, cfg.NitroEnclave)
	require.NotNil(t, cfg.Client)

	require.False(t, cfg.NitroEnclave.Enabled)
	require.Equal(t, uint32(enclaveDefaultCID), cfg.NitroEnclave.CID)
	require.Equal(t, uint32(10350), cfg.NitroEnclave.Port)

	require.Equal(t, providerName, cfg.Client.Name)
	require.Equal(t, enclaveDefaultURL, cfg.Client.BaseURL)
	require.Equal(t, defaultSignMessageTimeoutMS, cfg.Client.RequestTimeoutMS)
	require.NotNil(t, cfg.Client.Retry)
	require.Equal(t, uint(1), cfg.Client.Retry.MaxAttempts)
	require.Equal(t, DefaultMethodTimeouts(), cfg.Client.Methods)
	require.Equal(t, uint(1), cfg.Client.Methods["initialize"].MaxAttempts)
	require.Equal(t, 30*time.Second, cfg.StartupTimeout())
}

func TestProviderConfig_StartupTimeoutUsesIndependentTotalBudget(t *testing.T) {
	cfg := NewProviderConfig()
	cfg.StartupTimeoutMS = 1250
	cfg.Client.Methods["initialize"] = grpcClient.MethodConfig{TimeoutMS: 60000}

	require.Equal(t, 1250*time.Millisecond, cfg.StartupTimeout())
}
