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
	"fmt"
	"net"
	"time"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
)

// tcpDialTimeout bounds an in-flight upstream TCP dial in TCP transport
// mode so a hung dev endpoint does not pin Shutdown past its deadline.
const tcpDialTimeout = 10 * time.Second

// tcpListenHost is the bind host used in TCP transport mode. Dev/CI is
// the only consumer of this transport; the proxy and its caller live in
// different containers (compose, smoke), so the listener must accept
// remote dials.
const tcpListenHost = "0.0.0.0"

// tcpLocalstackEndpoint is the LocalStack target. The compose service name
// and the default LocalStack port are fixed.
const tcpLocalstackEndpoint = "localstack:4566"

// WithTCPTransport selects TCP transport for development and CI. It also
// sets the LocalStack target for configurations that enable LocalStack.
// The transport installs its listen and dial functions. The last transport
// option wins when a caller passes more than one option.
func WithTCPTransport() Option {
	return func(o *options) {
		o.transport = byteproxy.TransportTCP
		o.tcpLocalstackEndpoint = tcpLocalstackEndpoint
		o.listen = tcpListen(tcpListenHost)
		o.dial = tcpDial
	}
}

// tcpListen returns a listenFunc that binds host:<port> on TCP. Used
// when WithTCPTransport is selected.
func tcpListen(host string) listenFunc {
	return func(port uint32) (net.Listener, error) {
		return net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	}
}

// tcpDial opens a TCP connection to the resolved upstream endpoint. The
// ctx is forwarded from byteproxy.Shutdown so a stalled TCP handshake
// aborts promptly during lifecycle shutdown.
func tcpDial(ctx context.Context, endpoint string) (net.Conn, error) {
	d := net.Dialer{Timeout: tcpDialTimeout}
	return d.DialContext(ctx, "tcp", endpoint)
}
