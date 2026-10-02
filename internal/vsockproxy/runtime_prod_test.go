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

//go:build linux && prod

package vsockproxy

import (
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
	"github.com/stretchr/testify/require"
)

func TestApplyBuildPolicy_EnforcesProductionSettings(t *testing.T) {
	cfg := NewConfig()
	cfg.Vsockproxy.BasePort = 1
	cfg.Provider.Enclave.NitroEnclave.Enabled = false
	cfg.Provider.AWSKMS.Localstack.Enabled = true

	applyBuildPolicy(cfg)

	require.Equal(t, DefaultBasePort, cfg.Vsockproxy.BasePort)
	require.True(t, cfg.Provider.Enclave.NitroEnclave.Enabled)
	require.False(t, cfg.Provider.AWSKMS.Localstack.Enabled)

	options := options{}
	runtimeTransportOption(cfg)(&options)
	require.Equal(t, byteproxy.TransportVsock, options.transport)
}
