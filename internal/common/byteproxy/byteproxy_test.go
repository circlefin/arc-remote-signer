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

package byteproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// ByteProxyTestSuite tests the shared byte-proxy framework using in-memory
// TCP listeners as both the inbound and upstream sides, so the suite has no
// dependency on vsock or any other transport.
type ByteProxyTestSuite struct {
	suite.Suite
}

// newLocalListener returns a TCP listener bound to a random loopback port.
func (s *ByteProxyTestSuite) newLocalListener() net.Listener {
	s.T().Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	s.Require().NoError(err)
	s.T().Cleanup(func() { _ = ln.Close() })
	return ln
}

// startEcho accepts a single connection from ln and echoes everything back.
func (s *ByteProxyTestSuite) startEcho(ln net.Listener) {
	s.T().Helper()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(conn, conn)
	}()
}

// startProxy creates a proxy, calls Run(), and registers Shutdown with
// t.Cleanup. It also asserts that Run is non-blocking by failing fast if
// it does not return promptly — guarding the lifecycle.Runnable contract.
func (s *ByteProxyTestSuite) startProxy(cfg *Config) Proxy {
	s.T().Helper()
	p, err := New(cfg)
	s.Require().NoError(err)

	runDone := make(chan struct{})
	go func() {
		_ = p.Run()
		close(runDone)
	}()
	select {
	case <-runDone:
	case <-time.After(time.Second):
		s.FailNow("Run() did not return promptly; it must be non-blocking per lifecycle.Runnable")
	}

	s.T().Cleanup(func() { _ = p.Shutdown(context.Background()) })
	return p
}

// TestNew covers constructor validation in a table-driven form.
func (s *ByteProxyTestSuite) TestNew() {
	okListen := func() (net.Listener, error) {
		return s.newLocalListener(), nil
	}
	okDial := func(_ context.Context, _ net.Conn) (net.Conn, error) { return nil, errors.New("not used") }
	failingListen := func() (net.Listener, error) { return nil, errors.New("bind failed") }

	tests := map[string]struct {
		cfg     *Config
		wantErr bool
	}{
		"NilConfig": {
			cfg:     nil,
			wantErr: true,
		},
		"MissingName": {
			cfg: &Config{
				Services: []ServiceConfig{{Name: "kms", Listen: okListen, Dial: okDial}},
				MaxConns: 4,
			},
			wantErr: true,
		},
		"NoServices": {
			cfg:     &Config{Name: "test", MaxConns: 4},
			wantErr: true,
		},
		"InvalidMaxConns": {
			cfg: &Config{
				Name:     "test",
				Services: []ServiceConfig{{Name: "kms", Listen: okListen, Dial: okDial}},
				MaxConns: 0,
			},
			wantErr: true,
		},
		"MissingListen": {
			cfg: &Config{
				Name:     "test",
				Services: []ServiceConfig{{Name: "kms", Dial: okDial}},
				MaxConns: 4,
			},
			wantErr: true,
		},
		"MissingDial": {
			cfg: &Config{
				Name:     "test",
				Services: []ServiceConfig{{Name: "kms", Listen: okListen}},
				MaxConns: 4,
			},
			wantErr: true,
		},
		"BindFailure": {
			cfg: &Config{
				Name:     "test",
				Services: []ServiceConfig{{Name: "kms", Listen: failingListen, Dial: okDial}},
				MaxConns: 4,
			},
			wantErr: true,
		},
	}
	for name, tt := range tests {
		s.Run(name, func() {
			p, err := New(tt.cfg)
			if tt.wantErr {
				s.Require().Error(err)
				return
			}
			s.Require().NoError(err)
			s.NotNil(p)
		})
	}
}

// TestRun_IsNonBlocking explicitly verifies that Run() returns immediately,
// since lifecycle.Manager calls each Runnable's Run synchronously and would
// stall on the next service if Run blocked.
func (s *ByteProxyTestSuite) TestRun_IsNonBlocking() {
	inbound := s.newLocalListener()
	p, err := New(&Config{
		Name:     "test",
		MaxConns: 4,
		Services: []ServiceConfig{{
			Name:   "kms",
			Listen: func() (net.Listener, error) { return inbound, nil },
			Dial:   func(_ context.Context, _ net.Conn) (net.Conn, error) { return nil, errors.New("not used") },
		}},
	})
	s.Require().NoError(err)
	s.T().Cleanup(func() { _ = p.Shutdown(context.Background()) })

	returned := make(chan error, 1)
	go func() { returned <- p.Run() }()
	select {
	case err := <-returned:
		s.Require().NoError(err)
	case <-time.After(500 * time.Millisecond):
		s.FailNow("Run() did not return; it must be non-blocking")
	}
}

// TestProxy_BidirectionalCopy verifies bytes flow both ways between inbound
// and upstream.
func (s *ByteProxyTestSuite) TestProxy_BidirectionalCopy() {
	upstream := s.newLocalListener()
	s.startEcho(upstream)

	inbound := s.newLocalListener()
	p := s.startProxy(&Config{
		Name:     "test",
		MaxConns: 4,
		Services: []ServiceConfig{{
			Name:   "kms",
			Listen: func() (net.Listener, error) { return inbound, nil },
			Dial: func(_ context.Context, _ net.Conn) (net.Conn, error) {
				return net.Dial("tcp", upstream.Addr().String())
			},
		}},
	})
	_ = p

	conn, err := net.Dial("tcp", inbound.Addr().String())
	s.Require().NoError(err)
	defer func() { _ = conn.Close() }()

	payload := []byte("hello-from-sdk")
	_, err = conn.Write(payload)
	s.Require().NoError(err)

	buf := make([]byte, len(payload))
	s.Require().NoError(conn.SetReadDeadline(time.Now().Add(2 * time.Second)))
	_, err = io.ReadFull(conn, buf)
	s.Require().NoError(err)
	s.Equal(payload, buf)
}

func (s *ByteProxyTestSuite) TestProxy_DialCanReadInboundRouteBeforeBridge() {
	upstream := s.newLocalListener()
	s.startEcho(upstream)

	inbound := s.newLocalListener()
	routes := make(chan AWSRoute, 1)
	s.startProxy(&Config{
		Name:     "test",
		MaxConns: 4,
		Services: []ServiceConfig{{
			Name:   "kms",
			Listen: func() (net.Listener, error) { return inbound, nil },
			Dial: func(_ context.Context, accepted net.Conn) (net.Conn, error) {
				route, err := ReadAWSRoute(accepted)
				if err != nil {
					return nil, err
				}
				routes <- route
				return net.Dial("tcp", upstream.Addr().String())
			},
		}},
	})

	conn, err := net.Dial("tcp", inbound.Addr().String())
	s.Require().NoError(err)
	defer func() { _ = conn.Close() }()

	wantRoute := AWSRoute{Service: "kms", Region: "us-west-2"}
	s.Require().NoError(WriteAWSRoute(conn, wantRoute))
	payload := []byte("hello-after-route")
	_, err = conn.Write(payload)
	s.Require().NoError(err)

	buf := make([]byte, len(payload))
	s.Require().NoError(conn.SetReadDeadline(time.Now().Add(2 * time.Second)))
	_, err = io.ReadFull(conn, buf)
	s.Require().NoError(err)
	s.Equal(payload, buf)
	s.Equal(wantRoute, <-routes)
}

// TestProxy_HalfClose verifies the proxy closes the peer side when one side
// ends. Synchronisation uses a signal channel from the upstream-side echo
// rather than time.Sleep, so the test is deterministic under CI load.
func (s *ByteProxyTestSuite) TestProxy_HalfClose() {
	upstream := s.newLocalListener()
	peerClosed := make(chan struct{})
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(io.Discard, conn)
		close(peerClosed)
	}()

	inbound := s.newLocalListener()
	s.startProxy(&Config{
		Name:     "test",
		MaxConns: 4,
		Services: []ServiceConfig{{
			Name:   "kms",
			Listen: func() (net.Listener, error) { return inbound, nil },
			Dial: func(_ context.Context, _ net.Conn) (net.Conn, error) {
				return net.Dial("tcp", upstream.Addr().String())
			},
		}},
	})

	conn, err := net.Dial("tcp", inbound.Addr().String())
	s.Require().NoError(err)
	_, err = conn.Write([]byte("payload"))
	s.Require().NoError(err)
	s.Require().NoError(conn.Close())

	select {
	case <-peerClosed:
	case <-time.After(2 * time.Second):
		s.FailNow("upstream did not observe EOF after inbound close; half-close did not propagate")
	}
}

// TestProxy_DialFailureClosesConnection verifies that a failed upstream dial
// does not leave the inbound connection open.
func (s *ByteProxyTestSuite) TestProxy_DialFailureClosesConnection() {
	inbound := s.newLocalListener()
	s.startProxy(&Config{
		Name:     "test",
		MaxConns: 4,
		Services: []ServiceConfig{{
			Name:     "kms",
			Endpoint: "kms.example.com:443",
			Listen:   func() (net.Listener, error) { return inbound, nil },
			Dial:     func(_ context.Context, _ net.Conn) (net.Conn, error) { return nil, errors.New("dial failed") },
		}},
	})

	conn, err := net.Dial("tcp", inbound.Addr().String())
	s.Require().NoError(err)
	defer func() { _ = conn.Close() }()

	s.Require().NoError(conn.SetReadDeadline(time.Now().Add(2 * time.Second)))
	buf := make([]byte, 16)
	_, err = conn.Read(buf)
	s.Require().ErrorIs(err, io.EOF)
}

// TestProxy_DroppedCount verifies that connections rejected because the
// per-service concurrency cap is full are counted.
func (s *ByteProxyTestSuite) TestProxy_DroppedCount() {
	// release is closed early — before Shutdown — so the upstream goroutines
	// that hold connections can exit cleanly without depending on pipe's
	// shutdown branch to unblock them. defer runs in LIFO before t.Cleanup,
	// so this fires first.
	release := make(chan struct{})
	defer close(release)

	// Upstream accepts and holds connections until release is closed.
	upstream := s.newLocalListener()
	accepted := make(chan struct{}, 16)
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			go func(c net.Conn) {
				<-release
				_ = c.Close()
			}(conn)
		}
	}()

	inbound := s.newLocalListener()
	const maxConns = 2
	p := s.startProxy(&Config{
		Name:     "test",
		MaxConns: maxConns,
		Services: []ServiceConfig{{
			Name:   "kms",
			Listen: func() (net.Listener, error) { return inbound, nil },
			Dial: func(_ context.Context, _ net.Conn) (net.Conn, error) {
				return net.Dial("tcp", upstream.Addr().String())
			},
		}},
	})

	// Dial up to the cap and wait until upstream has accepted them, so the
	// per-service semaphore is provably full before we send the extras.
	holdConns := make([]net.Conn, 0, maxConns)
	for range maxConns {
		c, derr := net.Dial("tcp", inbound.Addr().String())
		s.Require().NoError(derr)
		holdConns = append(holdConns, c)
	}
	for range maxConns {
		select {
		case <-accepted:
		case <-time.After(2 * time.Second):
			s.FailNow("upstream did not accept the held connections in time")
		}
	}
	defer func() {
		for _, c := range holdConns {
			_ = c.Close()
		}
	}()

	// Now extras should be dropped. We dial and immediately observe EOF
	// because the proxy closes the inbound conn after sl.sem is full.
	const extras = 3
	for range extras {
		c, derr := net.Dial("tcp", inbound.Addr().String())
		s.Require().NoError(derr)
		s.Require().NoError(c.SetReadDeadline(time.Now().Add(2 * time.Second)))
		buf := make([]byte, 1)
		_, err := c.Read(buf)
		s.Require().ErrorIs(err, io.EOF)
		_ = c.Close()
	}

	s.Equal(int64(extras), p.DroppedCount("kms"))
	s.Equal(int64(0), p.DroppedCount("nonexistent"))
}

// TestProxy_ShutdownDuringAccept exercises the "two shutdown checks" race
// path in acceptLoop: a listener whose Accept returns a real conn while
// shutdownCh is already closed. The conn must be closed by acceptLoop and
// not dispatched to a bridge.
func (s *ByteProxyTestSuite) TestProxy_ShutdownDuringAccept() {
	// We control the listener directly so we can race Shutdown against
	// Accept. acceptCh has one queued conn pre-shutdown.
	queued := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	closeCh := make(chan struct{})
	ln := &controllableListener{
		queued:    queued,
		acceptErr: acceptErr,
		closeCh:   closeCh,
	}

	dialed := make(chan struct{}, 1)
	p, err := New(&Config{
		Name:     "test",
		MaxConns: 4,
		Services: []ServiceConfig{{
			Name:   "kms",
			Listen: func() (net.Listener, error) { return ln, nil },
			Dial: func(_ context.Context, _ net.Conn) (net.Conn, error) {
				dialed <- struct{}{}
				return nil, errors.New("dial should not be called after shutdown")
			},
		}},
	})
	s.Require().NoError(err)

	s.Require().NoError(p.Run())

	// Pre-shutdown: queue a conn that acceptLoop will pick up.
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	// Now shut down BEFORE feeding the queued conn. This guarantees
	// shutdownCh is closed when Accept eventually returns.
	shutdownDone := make(chan struct{})
	go func() {
		_ = p.Shutdown(context.Background())
		close(shutdownDone)
	}()
	// Wait for shutdownCh to actually be closed before feeding the conn,
	// so the post-Accept gate sees it.
	// Shutdown's wg.Wait blocks on acceptLoop which is blocked on Accept,
	// so we drive the listener manually to feed the conn after a brief
	// moment for close(shutdownCh) to have happened. We use a sync
	// channel: controllableListener.closeCh fires when Close is called by
	// Shutdown, which happens AFTER close(shutdownCh). Wait for that.
	select {
	case <-closeCh:
		// listener.Close was called → shutdownCh is already closed.
		// Feed the queued conn so Accept returns it.
		queued <- serverConn
	case <-time.After(2 * time.Second):
		s.FailNow("listener Close was not invoked by Shutdown")
	}

	// acceptLoop should see the post-Accept shutdown check fire, close
	// serverConn, and exit without dialing. Wait briefly to confirm dial
	// is NOT called.
	select {
	case <-dialed:
		s.FailNow("Dial was called for a conn accepted post-shutdown; the second shutdown check failed")
	case <-time.After(100 * time.Millisecond):
		// expected: no dial
	}

	// Final Accept returns ErrClosed to wake acceptLoop.
	acceptErr <- net.ErrClosed

	select {
	case <-shutdownDone:
	case <-time.After(2 * time.Second):
		s.FailNow("Shutdown did not return")
	}
}

// controllableListener is a net.Listener whose Accept is driven by the test
// via channels. Used by TestProxy_ShutdownDuringAccept to interleave
// Accept return with shutdown signalling.
type controllableListener struct {
	queued    chan net.Conn
	acceptErr chan error
	closeCh   chan struct{}
	closeOnce sync.Once
}

func (l *controllableListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.queued:
		return c, nil
	case err := <-l.acceptErr:
		return nil, err
	}
}

func (l *controllableListener) Close() error {
	l.closeOnce.Do(func() { close(l.closeCh) })
	return nil
}

func (l *controllableListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// TestProxy_ShutdownCancelsInFlightDial verifies that Shutdown cancels the
// ctx handed to DialFunc, so cooperative dialers (those that honor ctx)
// abort instead of holding the WaitGroup open. This guards the liveness
// contract: a stalled upstream must not prevent lifecycle shutdown.
func (s *ByteProxyTestSuite) TestProxy_ShutdownCancelsInFlightDial() {
	dialing := make(chan struct{})
	dialReturned := make(chan error, 1)
	inbound := s.newLocalListener()
	p, err := New(&Config{
		Name:     "test",
		MaxConns: 4,
		Services: []ServiceConfig{{
			Name:   "kms",
			Listen: func() (net.Listener, error) { return inbound, nil },
			Dial: func(ctx context.Context, _ net.Conn) (net.Conn, error) {
				close(dialing)
				<-ctx.Done()
				dialReturned <- ctx.Err()
				return nil, ctx.Err()
			},
		}},
	})
	s.Require().NoError(err)
	s.Require().NoError(p.Run())

	// Drive one connection through the inbound listener so bridge starts
	// the dial and parks inside DialFunc waiting on ctx.
	conn, derr := net.Dial("tcp", inbound.Addr().String())
	s.Require().NoError(derr)
	defer func() { _ = conn.Close() }()
	select {
	case <-dialing:
	case <-time.After(2 * time.Second):
		s.FailNow("DialFunc was not invoked")
	}

	// Shutdown must observe the ctx cancellation propagating to the parked
	// dialer and drain promptly.
	shutdownErr := make(chan error, 1)
	go func() { shutdownErr <- p.Shutdown(context.Background()) }()

	select {
	case err := <-dialReturned:
		s.Require().ErrorIs(err, context.Canceled,
			"DialFunc ctx must be cancelled by Shutdown so cooperative dialers unblock")
	case <-time.After(2 * time.Second):
		s.FailNow("Shutdown did not cancel the in-flight dial ctx")
	}

	select {
	case err := <-shutdownErr:
		s.Require().NoError(err)
	case <-time.After(2 * time.Second):
		s.FailNow("Shutdown did not return after dial unblocked")
	}
}

// TestProxy_ShutdownHonorsContextDeadline verifies that Shutdown returns
// when its ctx expires even if a bridge goroutine refuses to honor the
// dial ctx (simulating a truly hung syscall). The dialer here ignores ctx
// entirely; Shutdown's wg.Wait would otherwise block forever.
func (s *ByteProxyTestSuite) TestProxy_ShutdownHonorsContextDeadline() {
	dialing := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	inbound := s.newLocalListener()
	p, err := New(&Config{
		Name:     "test",
		MaxConns: 4,
		Services: []ServiceConfig{{
			Name:   "kms",
			Listen: func() (net.Listener, error) { return inbound, nil },
			Dial: func(_ context.Context, _ net.Conn) (net.Conn, error) {
				close(dialing)
				<-release // ignore ctx, simulate uncancellable dial
				return nil, errors.New("released")
			},
		}},
	})
	s.Require().NoError(err)
	s.Require().NoError(p.Run())

	conn, derr := net.Dial("tcp", inbound.Addr().String())
	s.Require().NoError(derr)
	defer func() { _ = conn.Close() }()
	select {
	case <-dialing:
	case <-time.After(2 * time.Second):
		s.FailNow("DialFunc was not invoked")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = p.Shutdown(ctx)
	elapsed := time.Since(start)

	s.Require().Error(err)
	s.Require().ErrorIs(err, context.DeadlineExceeded,
		"Shutdown must surface ctx.Err() when the deadline expires before drain")
	s.Less(elapsed, time.Second,
		"Shutdown must return promptly once ctx expires, not wait for the hung dialer")
}

// TestByteProxyTestSuite is the entry point for the suite.
func TestByteProxyTestSuite(t *testing.T) {
	suite.Run(t, &ByteProxyTestSuite{Suite: suite.Suite{}})
}
