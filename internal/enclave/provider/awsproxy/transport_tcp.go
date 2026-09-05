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
	"fmt"
	"net"
	"time"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
)

// tcpDialTimeout bounds an in-flight upstream TCP dial in TCP transport
// mode so a hung dev parent host does not pin Shutdown past its deadline.
const tcpDialTimeout = 10 * time.Second

// tcpParentHost is the host the enclave reaches the parent vsockproxy on
// in TCP transport mode. Dev/CI is the only consumer; the compose service
// name "vsockproxy" is fixed, so it is hardcoded rather than configured.
const tcpParentHost = "vsockproxy"

// WithTCPTransport selects TCP transport. Dev/CI is the only consumer;
// the upstream target is the fixed vsockproxy host in compose. The
// transport's listen/dial are installed unconditionally so that when more
// than one transport option is passed the last one wins coherently; the
// WithListen/WithDial test seams still override because they are applied
// after the transport option.
func WithTCPTransport() Option {
	return func(o *options) {
		o.transport = byteproxy.TransportTCP
		o.tcpParentHost = tcpParentHost
		o.listen = tcpListenLoopback
		o.dial = tcpDialParent(tcpParentHost)
	}
}

// tcpListenLoopback binds 127.0.0.1:<port> on the enclave's loopback
// interface — the same listen address used in production. Production uses
// this same listener; only the dial side changes between transports.
func tcpListenLoopback(port uint32) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
}

// tcpDialParent returns a dialFunc that TCP-dials parentHost:<port> for
// each accepted session.
func tcpDialParent(parentHost string) dialFunc {
	return func(ctx context.Context, port uint32) (net.Conn, error) {
		d := net.Dialer{Timeout: tcpDialTimeout}
		return d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", parentHost, port))
	}
}
