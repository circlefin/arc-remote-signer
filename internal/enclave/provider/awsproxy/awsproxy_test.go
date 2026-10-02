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
	"errors"
	"net"
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
	"github.com/stretchr/testify/suite"
)

// AwsProxyTestSuite covers the wrapper-specific behaviour layered on top of
// the byteproxy framework: transport selection, port mapping per service,
// and bind failure propagation. Bidirectional copy, half-close, and dial
// failure are covered by the byteproxy package tests.
type AwsProxyTestSuite struct {
	suite.Suite
}

// newLocalListener returns a TCP listener bound to a random loopback port.
func (s *AwsProxyTestSuite) newLocalListener() net.Listener {
	s.T().Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	s.Require().NoError(err)
	s.T().Cleanup(func() { _ = ln.Close() })
	return ln
}

// shutdownOnCleanup releases the listeners a successfully constructed proxy
// bound and, unlike a bare deferred Shutdown, keeps a happy-path Shutdown
// regression (resource leak, double-close error) visible: a non-nil error
// fails the test. Reported via t.Errorf rather than require because the
// repo policy forbids FailNow-triggering assertions inside t.Cleanup.
func (s *AwsProxyTestSuite) shutdownOnCleanup(p Provider) {
	s.T().Helper()
	s.T().Cleanup(func() {
		if err := p.Shutdown(context.Background()); err != nil {
			s.T().Errorf("Shutdown returned error: %v", err)
		}
	})
}

// TestNew covers constructor validation and transport selection in a
// table-driven form.
func (s *AwsProxyTestSuite) TestNew() {
	failingListen := func(_ uint32) (net.Listener, error) { return nil, errors.New("bind failed") }
	failingDial := func(_ context.Context, _ uint32) (net.Conn, error) { return nil, errors.New("not used") }
	okListen := func(_ uint32) (net.Listener, error) { return s.newLocalListener(), nil }

	tests := map[string]struct {
		cfg     *Config
		opts    []Option
		wantErr bool
	}{
		"NilConfig": {
			cfg:     nil,
			opts:    []Option{WithListen(failingListen), WithDial(failingDial)},
			wantErr: true,
		},
		"InvalidMaxConns_VsockTransport": {
			cfg:     &Config{BasePort: 30000, MaxConns: 0},
			opts:    []Option{WithVsockTransport(), WithListen(okListen), WithDial(failingDial)},
			wantErr: true,
		},
		"BindFailure_VsockTransport": {
			cfg:     &Config{BasePort: 30000, MaxConns: 4},
			opts:    []Option{WithVsockTransport(), WithListen(failingListen), WithDial(failingDial)},
			wantErr: true,
		},
		"HappyPath_VsockTransport": {
			cfg:     &Config{BasePort: 30000, MaxConns: 4},
			opts:    []Option{WithVsockTransport(), WithListen(okListen), WithDial(failingDial)},
			wantErr: false,
		},
		"HappyPath_TCPTransport": {
			cfg:     &Config{BasePort: 30000, MaxConns: 4},
			opts:    []Option{WithTCPTransport(), WithListen(okListen), WithDial(failingDial)},
			wantErr: false,
		},
		// No transport option falls back to the vsock zero value; the
		// supplied listen/dial seams let New succeed without a real vsock.
		"NoTransportOption_DefaultsToVsock": {
			cfg:     &Config{BasePort: 30000, MaxConns: 4},
			opts:    []Option{WithListen(okListen), WithDial(failingDial)},
			wantErr: false,
		},
		"BothTransportOptions_LastWins_Succeeds": {
			cfg:     &Config{BasePort: 30000, MaxConns: 4},
			opts:    []Option{WithVsockTransport(), WithTCPTransport(), WithListen(okListen), WithDial(failingDial)},
			wantErr: false,
		},
	}
	for name, tt := range tests {
		s.Run(name, func() {
			p, err := New(tt.cfg, tt.opts...)
			if tt.wantErr {
				s.Require().Error(err)
				return
			}
			s.Require().NoError(err)
			s.Require().NotNil(p)
			s.shutdownOnCleanup(p)
		})
	}
}

// TestNew_PortMapping verifies that each service in byteproxy.AWSServiceNames
// maps to BasePort + index, that listen is called once per service, and that
// the service name flows through to the byteproxy ServiceConfig. The
// assertion is non-vacuous because AWSServiceNames is required to be
// non-empty.
func (s *AwsProxyTestSuite) TestNew_PortMapping() {
	s.Require().NotEmpty(byteproxy.AWSServiceNames, "AWSServiceNames must declare at least one service")

	var seenPorts []uint32
	listen := func(port uint32) (net.Listener, error) {
		seenPorts = append(seenPorts, port)
		return s.newLocalListener(), nil
	}
	dial := func(_ context.Context, _ uint32) (net.Conn, error) { return nil, errors.New("dial unused") }

	const base uint32 = 40000
	p, err := New(
		&Config{BasePort: base, MaxConns: 4},
		WithVsockTransport(), WithListen(listen), WithDial(dial),
	)
	s.Require().NoError(err)
	s.shutdownOnCleanup(p)

	wantPorts := make([]uint32, len(byteproxy.AWSServiceNames))
	for i := range byteproxy.AWSServiceNames {
		wantPorts[i] = base + uint32(i) //nolint:gosec // bounded by len(AWSServiceNames)
	}
	s.Equal(wantPorts, seenPorts)
	s.Len(seenPorts, len(byteproxy.AWSServiceNames),
		"listen must be called exactly once per service")
}

// TestWithTransport_LastWins verifies that passing both transport options
// is not an error and that the last option applied selects the transport,
// including its TCP parent host, so the selected kind and its dialer stay
// coherent.
func (s *AwsProxyTestSuite) TestWithTransport_LastWins() {
	s.Run("tcp last", func() {
		o := options{}
		WithVsockTransport()(&o)
		WithTCPTransport()(&o)
		s.Equal(byteproxy.TransportTCP, o.transport)
		s.Equal(tcpParentHost, o.tcpParentHost)
	})
	s.Run("vsock last", func() {
		o := options{}
		WithTCPTransport()(&o)
		WithVsockTransport()(&o)
		s.Equal(byteproxy.TransportVsock, o.transport)
	})
}

// TestNew_UnhandledTransportKind covers describeEndpoint's default guard:
// an out-of-range transport (e.g. a future byteproxy.TransportKind added
// without a matching case) must surface an error from New rather than
// silently logging an empty endpoint. Injected via a raw Option so the
// guard stays protected from silent removal.
func (s *AwsProxyTestSuite) TestNew_UnhandledTransportKind() {
	badTransport := Option(func(o *options) { o.transport = byteproxy.TransportKind(99) })
	_, err := New(&Config{BasePort: 30000, MaxConns: 4}, badTransport)
	s.Require().Error(err)
	s.Contains(err.Error(), "unhandled transport kind")
}

// TestAwsProxyTestSuite is the entry point for the suite.
func TestAwsProxyTestSuite(t *testing.T) {
	suite.Run(t, &AwsProxyTestSuite{Suite: suite.Suite{}})
}
