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

//go:build !prod

package enclave

import (
	"context"
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awsproxy"
	"github.com/stretchr/testify/require"
)

func shutdownAWSProxyOnCleanup(t *testing.T, pvd awsproxy.Provider) {
	t.Helper()
	t.Cleanup(func() {
		if err := pvd.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown AWS proxy: %v", err)
		}
	})
}

// TestSelectTransport checks development transport selection.
// Nitro configuration uses VSOCK. Other configuration uses TCP.
func TestSelectTransport(t *testing.T) {
	tests := map[string]struct {
		enabled bool
		want    transportKind
	}{
		"nitro enabled selects vsock": {enabled: true, want: transportVsock},
		"nitro disabled selects tcp":  {enabled: false, want: transportTCP},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.NitroEnclave.Enabled = tt.enabled
			require.Equal(t, tt.want, selectTransport(cfg))
		})
	}
}

func TestBuildAWSProxy_SelectsTCP(t *testing.T) {
	cfg := NewConfig()
	cfg.NitroEnclave.Enabled = false

	pvd, err := buildAWSProxy(cfg)

	require.NoError(t, err)
	require.NotNil(t, pvd)
	shutdownAWSProxyOnCleanup(t, pvd)
}
