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

//go:build !linux

package awsproxy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// stubCfg seeds BasePort: 0 so the OS assigns an ephemeral loopback port
// later, when New()'s TCP transport actually calls net.Listen; this lets
// the TCP happy path bind without a fixed-port conflict.
func stubCfg() *Config {
	return &Config{BasePort: 0, MaxConns: 1}
}

func TestNew_NilConfigErrors(t *testing.T) {
	_, err := New(nil, WithTCPTransport())
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil config")
}

// TestNew_NoTransportOptionErrors pins the non-Linux gate: the zero-value
// transport is vsock, which the stub cannot serve, so a call without
// WithTCPTransport() must error rather than silently no-op.
func TestNew_NoTransportOptionErrors(t *testing.T) {
	_, err := New(stubCfg())
	require.Error(t, err)
	require.Contains(t, err.Error(), "requires WithTCPTransport")
}

func TestNew_TCPTransportSucceeds(t *testing.T) {
	p, err := New(stubCfg(), WithTCPTransport())
	require.NoError(t, err)
	require.NotNil(t, p)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
}
