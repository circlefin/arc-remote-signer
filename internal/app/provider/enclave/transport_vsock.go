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

package enclave

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/vsock"
)

// DialFunc is a function type that establishes a network connection.
type DialFunc func() (net.Conn, error)

// DefaultDialTimeout is the default timeout for dial operations.
const DefaultDialTimeout = 3 * time.Second

// cleanupTimeout is the additional time we wait for a dial operation to complete
// after context cancellation, before giving up on cleanup. This ensures we don't leak
// connections from dial operations that complete shortly after timeout.
const cleanupTimeout = 1 * time.Second

var vsockDial = func(cid, port uint32) (net.Conn, error) {
	return vsock.Dial(cid, port, nil)
}

// NewVsockDialer creates a gRPC dialer function that connects over VSOCK.
func NewVsockDialer(cid, port uint32) func(ctx context.Context, _ string) (net.Conn, error) {
	return func(ctx context.Context, _ string) (net.Conn, error) {
		dialFn := func() (net.Conn, error) {
			return vsockDial(cid, port)
		}
		return dialWithContext(ctx, dialFn, DefaultDialTimeout)
	}
}

// dialWithContext wraps a dial function with context support.
// Since some dial implementations (like vsock.Dial) don't natively support context,
// we run the dial in a goroutine and handle cancellation manually.
func dialWithContext(ctx context.Context, dialFn DialFunc, timeout time.Duration) (net.Conn, error) {
	type dialResult struct {
		conn net.Conn
		err  error
	}

	resultCh := make(chan dialResult, 1)
	go func() {
		conn, err := dialFn()
		resultCh <- dialResult{conn, err}
	}()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case <-ctx.Done():
		// Context cancelled - clean up if dial eventually succeeds
		go func() {
			select {
			case r := <-resultCh:
				if r.conn != nil {
					_ = r.conn.Close()
				}
			case <-time.After(cleanupTimeout):
				// Give up waiting for dial to complete after grace period.
				return
			}
		}()
		return nil, fmt.Errorf("dial timeout: %w", ctx.Err())
	case r := <-resultCh:
		return r.conn, r.err
	}
}
