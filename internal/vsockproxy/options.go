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

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
)

// listenFunc binds a listener for the given service port.
type listenFunc func(port uint32) (net.Listener, error)

// dialFunc opens an upstream connection. The endpoint string is opaque to
// the byteproxy framework; the wrapper decides what it means.
type dialFunc func(ctx context.Context, endpoint string) (net.Conn, error)

// options carries injection points and the selected transport.
type options struct {
	listen    listenFunc
	dial      dialFunc
	transport byteproxy.TransportKind
	// tcpLocalstackEndpoint is the upstream dial target in TCP mode; ignored in vsock mode.
	tcpLocalstackEndpoint string
}

// Option customises New. Transport-selection options
// (WithVsockTransport / WithTCPTransport) and test seams (WithListen /
// WithDial) all use this single type.
type Option func(*options)

// WithListen overrides the listener for tests. Production callers should
// rely on the default produced by the selected transport. Must be passed
// AFTER any transport-selection option (WithVsockTransport / WithTCPTransport),
// which install listen/dial unconditionally and would otherwise overwrite
// this override.
func WithListen(fn listenFunc) Option { return func(o *options) { o.listen = fn } }

// WithDial overrides the upstream dialer for tests. Production callers
// should rely on the default produced by the selected transport. Must be
// passed AFTER any transport-selection option (WithVsockTransport /
// WithTCPTransport), which install listen/dial unconditionally and would
// otherwise overwrite this override.
func WithDial(fn dialFunc) Option { return func(o *options) { o.dial = fn } }
