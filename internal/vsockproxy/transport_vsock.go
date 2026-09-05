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

//go:build linux

package vsockproxy

import (
	"context"
	"net"
	"time"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
	"github.com/mdlayher/vsock"
)

// vsockDialTimeout bounds the upstream TCP dial when vsockproxy bridges
// vsock-accept → TCP-AWS.
const vsockDialTimeout = 10 * time.Second

// WithVsockTransport selects the production vsock transport: vsock listen
// on the configured BasePort, TCP dial to the resolved AWS endpoint.
// References to this option do not compile on non-Linux platforms. The
// transport's listen/dial are installed unconditionally so that when more
// than one transport option is passed the last one wins coherently; the
// WithListen/WithDial test seams still override because they are applied
// after the transport option.
func WithVsockTransport() Option {
	return func(o *options) {
		o.transport = byteproxy.TransportVsock
		o.listen = vsockListen
		o.dial = vsockDial
	}
}

// vsockListen binds a VSOCK listener to the Nitro parent CID for the given port.
func vsockListen(port uint32) (net.Listener, error) {
	return listenNitroParentVsock(port, listenVsockContextID)
}

// listenVsockContextID binds directly to contextID without discovering the local CID.
// Do not replace this with vsock.Listen: it opens /dev/vsock, which is not exposed
// to the Kubernetes signer container.
func listenVsockContextID(contextID, port uint32) (net.Listener, error) {
	return vsock.ListenContextID(contextID, port, &vsock.Config{})
}

// vsockDial opens a TCP connection to the given AWS endpoint. The ctx is
// forwarded from byteproxy.Shutdown so a stalled TCP handshake aborts
// promptly during lifecycle shutdown.
func vsockDial(ctx context.Context, endpoint string) (net.Conn, error) {
	d := net.Dialer{Timeout: vsockDialTimeout}
	return d.DialContext(ctx, "tcp", endpoint)
}
