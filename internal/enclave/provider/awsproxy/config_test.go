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

package awsproxy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewConfig_Defaults pins the config defaults. Operators rely on these
// constants when wiring deployment YAML and gateway-tee-signer parity, so
// changing them without intent would silently shift port assignments.
func TestNewConfig_Defaults(t *testing.T) {
	cfg := NewConfig()

	require.NotNil(t, cfg)
	require.Equal(t, DefaultBasePort, cfg.BasePort)
	require.Equal(t, DefaultMaxConns, cfg.MaxConns)

	// Default constants documented to match gateway-tee-signer.
	require.Equal(t, uint32(10316), DefaultBasePort,
		"DefaultBasePort must match gateway-tee-signer's aws_proxy_port default")
	require.Equal(t, 50, DefaultMaxConns,
		"DefaultMaxConns must match gateway-tee-signer's socat max-children=50")
}
