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
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mockConn implements net.Conn for testing.
type mockConn struct {
	closed   bool
	onClose  func()
	closeErr error
}

func (m *mockConn) Read(_ []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(_ time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(_ time.Time) error { return nil }

func (m *mockConn) Close() error {
	m.closed = true
	if m.onClose != nil {
		m.onClose()
	}
	return m.closeErr
}

func TestNewVsockDialer(t *testing.T) {
	cid := uint32(16)
	port := uint32(10350)
	dialer := NewVsockDialer(cid, port)

	require.NotNil(t, dialer)
}

func TestNewVsockDialer_UsesVsockDial(t *testing.T) {
	originalVsockDial := vsockDial
	t.Cleanup(func() { vsockDial = originalVsockDial })

	expectedConn := &mockConn{}
	var gotCID, gotPort uint32
	vsockDial = func(cid, port uint32) (net.Conn, error) {
		gotCID = cid
		gotPort = port
		return expectedConn, nil
	}

	cid := uint32(16)
	port := uint32(10350)
	dialer := NewVsockDialer(cid, port)

	conn, err := dialer(context.Background(), "ignored-target")
	require.NoError(t, err)
	require.Equal(t, expectedConn, conn)
	require.Equal(t, cid, gotCID)
	require.Equal(t, port, gotPort)
}

func TestNewVsockDialer_PropagatesVsockDialError(t *testing.T) {
	originalVsockDial := vsockDial
	t.Cleanup(func() { vsockDial = originalVsockDial })

	expectedErr := errors.New("dial failed")
	vsockDial = func(_, _ uint32) (net.Conn, error) {
		return nil, expectedErr
	}

	dialer := NewVsockDialer(16, 10350)

	conn, err := dialer(context.Background(), "ignored-target")
	require.Nil(t, conn)
	require.ErrorIs(t, err, expectedErr)
}

func TestDialWithContext_QuickSuccess(t *testing.T) {
	expectedConn := &mockConn{}
	dialFn := func() (net.Conn, error) {
		return expectedConn, nil
	}

	ctx := context.Background()
	conn, err := dialWithContext(ctx, dialFn, DefaultDialTimeout)

	require.NoError(t, err)
	require.Equal(t, expectedConn, conn)
}

func TestDialWithContext_QuickError(t *testing.T) {
	expectedErr := io.EOF
	dialFn := func() (net.Conn, error) {
		return nil, expectedErr
	}

	ctx := context.Background()
	conn, err := dialWithContext(ctx, dialFn, DefaultDialTimeout)

	require.Nil(t, conn)
	require.ErrorIs(t, err, expectedErr)
}

func TestDialWithContext_AlreadyCancelled(t *testing.T) {
	release := make(chan struct{})
	dialFn := func() (net.Conn, error) {
		<-release
		return &mockConn{}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	conn, err := dialWithContext(ctx, dialFn, DefaultDialTimeout)
	close(release)

	require.Nil(t, conn)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
	require.Contains(t, err.Error(), "dial timeout")
}

func TestDialWithContext_Timeout(t *testing.T) {
	dialFn := func() (net.Conn, error) {
		time.Sleep(500 * time.Millisecond) // Slow dial
		return &mockConn{}, nil
	}

	ctx := context.Background()
	conn, err := dialWithContext(ctx, dialFn, 50*time.Millisecond) // Short timeout

	require.Nil(t, conn)
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Contains(t, err.Error(), "dial timeout")
}

func TestDialWithContext_TimeoutCleansUpConnection(t *testing.T) {
	connClosed := make(chan struct{}, 1)
	mockConn := &mockConn{
		onClose: func() {
			connClosed <- struct{}{}
		},
	}

	dialFn := func() (net.Conn, error) {
		time.Sleep(50 * time.Millisecond) // Simulate slow dial that completes within grace period
		return mockConn, nil
	}

	testTimeout := 10 * time.Millisecond
	ctx := context.Background()
	conn, err := dialWithContext(ctx, dialFn, testTimeout)

	require.Nil(t, conn)
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	// Wait for cleanup goroutine to close the connection.
	// Cleanup waits for timeout + cleanupGracePeriod = 10ms + 1s.
	// Since dial completes in 50ms, cleanup should happen well before the grace period expires.
	require.Eventually(t, func() bool {
		select {
		case <-connClosed:
			return true
		default:
			return false
		}
	}, 300*time.Millisecond, 10*time.Millisecond, "connection should be closed by cleanup")
}
