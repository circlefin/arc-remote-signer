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

package enclave

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBuildAWSProxy_SelectsVSOCK checks VSOCK provider construction in development.
// TestSelectTransport checks only the transport value. The VSOCK provider compiles
// only on Linux. Construction does not start the listener or require a VSOCK device.
func TestBuildAWSProxy_SelectsVSOCK(t *testing.T) {
	cfg := NewConfig()
	cfg.NitroEnclave.Enabled = true

	pvd, err := buildAWSProxy(cfg)

	require.NoError(t, err)
	require.NotNil(t, pvd)
	shutdownAWSProxyOnCleanup(t, pvd)
}
