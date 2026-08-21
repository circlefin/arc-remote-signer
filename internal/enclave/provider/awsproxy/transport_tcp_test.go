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
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTCPListenLoopback_BindsLoopback(t *testing.T) {
	ln, err := tcpListenLoopback(0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	addr, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok)
	require.Equal(t, "127.0.0.1", addr.IP.String(),
		"awsproxy TCP listener must bind 127.0.0.1 inside the enclave")
}

func TestTCPDialParent_ReachesTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	addr, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok)

	dial := tcpDialParent("127.0.0.1")
	conn, err := dial(context.Background(), uint32(addr.Port)) //nolint:gosec // bounded by ephemeral port range
	require.NoError(t, err)
	require.NoError(t, conn.Close())
}
