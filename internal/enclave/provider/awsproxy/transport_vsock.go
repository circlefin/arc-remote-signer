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

package awsproxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
	"github.com/mdlayher/vsock"
)

// parentCID is the well-known vsock context ID for the parent EC2 instance.
const parentCID uint32 = 3

// vsockDialTimeout bounds an in-flight vsock dial, matching the 10s bound
// the TCP path gets from net.Dialer.Timeout. mdlayher/vsock exposes no
// dial deadline, so we race vsock.Dial against this timeout (and against
// ctx.Done) rather than configuring one on the dialer.
const vsockDialTimeout = 10 * time.Second

// WithVsockTransport selects the production vsock transport: loopback
// listen on the configured BasePort, vsock dial to the parent CID for
// each accepted session. References to this option do not compile on
// non-Linux platforms. The transport's listen/dial are installed
// unconditionally so that when more than one transport option is passed
// the last one wins coherently; the WithListen/WithDial test seams still
// override because they are applied after the transport option.
func WithVsockTransport() Option {
	return func(o *options) {
		o.transport = byteproxy.TransportVsock
		o.listen = vsockTransportListen
		o.dial = vsockTransportDial
	}
}

// vsockTransportListen binds 127.0.0.1:<port> on the enclave's loopback
// interface (vsock transport still listens on TCP loopback; only the
// dial side is vsock).
func vsockTransportListen(port uint32) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
}

// vsockDialResult carries the outcome of vsock.Dial back to the racing
// dial.
type vsockDialResult struct {
	conn net.Conn
	err  error
}

// vsockTransportDial opens a vsock connection to the parent EC2 instance.
// vsock.Dial has no ctx hook and no dial deadline, so we race it against
// both ctx.Done() and vsockDialTimeout. Whichever loses, a hung dial would
// otherwise pin its byteproxy bridge slot forever and, once every MaxConns
// slot is stuck, the proxy would reject all new connections.
//
// On either abort we drain the buffered result in the background and close
// any conn that arrives late, so a slow-but-eventually-returning dial does
// not leak an fd. A dial that never returns still leaks two goroutines
// (the blocked vsock.Dial and its drainer) plus the fd (mdlayher/vsock
// cannot cancel an in-flight dial), but the bridge slot is released, which
// is the failure that matters.
func vsockTransportDial(ctx context.Context, port uint32) (net.Conn, error) {
	// A timeout context bounds the dial and unifies the two abort cases;
	// cancel() stops its timer on the success path so a per-dial timer does
	// not linger until it fires (unlike a bare time.After).
	dialCtx, cancel := context.WithTimeout(ctx, vsockDialTimeout)
	defer cancel()

	resultCh := make(chan vsockDialResult, 1)
	go func() {
		c, err := vsock.Dial(parentCID, port, nil)
		resultCh <- vsockDialResult{conn: c, err: err}
	}()
	select {
	case r := <-resultCh:
		return r.conn, r.err
	case <-dialCtx.Done():
		go drainVsockDial(resultCh)
		// dialCtx fires on either the parent ctx (Shutdown) or our timeout.
		// If the parent is done, propagate its error verbatim — its
		// DeadlineExceeded would otherwise be mis-reported as our timeout.
		// Only when the parent is still alive did our vsockDialTimeout fire.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("awsproxy: vsock dial to parent CID %d port %d timed out after %s, err: %w", parentCID, port, vsockDialTimeout, dialCtx.Err())
	}
}

// drainVsockDial waits for an abandoned vsock.Dial to return and closes any
// connection it produced, so an aborted dial does not leak the fd.
func drainVsockDial(resultCh <-chan vsockDialResult) {
	r := <-resultCh
	if r.conn != nil {
		_ = r.conn.Close()
	}
}
