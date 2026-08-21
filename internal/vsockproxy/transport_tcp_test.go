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

package vsockproxy

import (
	"context"
	"net"
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
	"github.com/stretchr/testify/require"
)

func TestTCPListen_BindsHost(t *testing.T) {
	listen := tcpListen("127.0.0.1")
	ln, err := listen(0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	addr, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok, "addr must be *net.TCPAddr")
	require.Equal(t, "127.0.0.1", addr.IP.String(),
		"tcpListen must bind the supplied host")
}

// TestWithTCPTransport_DefaultsToLocalstackEndpoint pins the upstream
// endpoint and listen host the TCP transport uses in dev/CI. compose and
// smoke depend on these defaults; a silent rename of the package
// constants would break those environments without any other test
// firing.
func TestWithTCPTransport_DefaultsToLocalstackEndpoint(t *testing.T) {
	o := options{}
	WithTCPTransport()(&o)
	require.Equal(t, byteproxy.TransportTCP, o.transport)
	require.Equal(t, "localstack:4566", o.tcpLocalstackEndpoint)
}

func TestTCPDial_Succeeds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	conn, err := tcpDial(context.Background(), ln.Addr().String())
	require.NoError(t, err)
	require.NoError(t, conn.Close())
}
