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
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type VsockProxyTestSuite struct {
	suite.Suite
}

func (s *VsockProxyTestSuite) newLocalListener() net.Listener {
	s.T().Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	s.Require().NoError(err)
	s.T().Cleanup(func() { _ = ln.Close() })
	return ln
}

// vsockCfg returns a vsock-mode Config with a single allowed us-east-1 ARN.
func vsockCfg(basePort uint32, maxConns int) *Config {
	return &Config{
		Vsockproxy: Vsockproxy{BasePort: basePort, MaxConns: maxConns},
		Provider: ProviderConfig{
			AWSKMS: ProviderAWSKMSConfig{
				Arns: []string{"arn:aws:kms:us-east-1:000000000000:key/abc"},
			},
		},
	}
}

func (s *VsockProxyTestSuite) TestNew() {
	failingListen := func(_ uint32) (net.Listener, error) { return nil, errors.New("bind failed") }
	failingDial := func(_ context.Context, _ string) (net.Conn, error) { return nil, errors.New("not used") }
	okListen := func(_ uint32) (net.Listener, error) { return s.newLocalListener(), nil }

	tests := map[string]struct {
		cfg             *Config
		opts            []Option
		wantErr         bool
		wantErrContains string
	}{
		"NilConfig": {
			cfg:     nil,
			opts:    []Option{WithListen(failingListen), WithDial(failingDial)},
			wantErr: true,
		},
		"InvalidMaxConns_VsockTransport": {
			cfg:     vsockCfg(30000, 0),
			opts:    []Option{WithVsockTransport(), WithListen(okListen), WithDial(failingDial)},
			wantErr: true,
		},
		"BindFailure_VsockTransport": {
			cfg:     vsockCfg(30000, 4),
			opts:    []Option{WithVsockTransport(), WithListen(failingListen), WithDial(failingDial)},
			wantErr: true,
		},
		"EnabledHappyPath_VsockTransport": {
			cfg:     vsockCfg(30000, 4),
			opts:    []Option{WithVsockTransport(), WithListen(okListen), WithDial(failingDial)},
			wantErr: false,
		},
		"EnabledHappyPath_TCPTransport": {
			cfg:     vsockCfg(30000, 4),
			opts:    []Option{WithTCPTransport(), WithListen(okListen), WithDial(failingDial)},
			wantErr: false,
		},
		// No transport option falls back to the vsock zero value; the
		// vsock-mode Config (ARN present) lets region resolution succeed.
		"NoTransportOption_DefaultsToVsock": {
			cfg:     vsockCfg(30000, 4),
			opts:    []Option{WithListen(okListen), WithDial(failingDial)},
			wantErr: false,
		},
		// vsock wins as the last transport option, so a vsock-mode Config
		// (ARN present for region resolution) is required for success.
		"BothTransportOptions_LastWins_Succeeds": {
			cfg:     vsockCfg(30000, 4),
			opts:    []Option{WithTCPTransport(), WithVsockTransport(), WithListen(okListen), WithDial(failingDial)},
			wantErr: false,
		},
		"NoArns_VsockTransport_Errors": {
			cfg:             &Config{Vsockproxy: Vsockproxy{BasePort: 30000, MaxConns: 4}},
			opts:            []Option{WithVsockTransport(), WithListen(okListen), WithDial(failingDial)},
			wantErr:         true,
			wantErrContains: "provider.awskms.arns",
		},
		"MalformedArn_VsockTransport_Errors": {
			cfg: &Config{
				Vsockproxy: Vsockproxy{BasePort: 30000, MaxConns: 4},
				Provider: ProviderConfig{
					AWSKMS: ProviderAWSKMSConfig{Arns: []string{"not-an-arn"}},
				},
			},
			opts:            []Option{WithVsockTransport(), WithListen(okListen), WithDial(failingDial)},
			wantErr:         true,
			wantErrContains: "not a valid ARN",
		},
		// A syntactically valid KMS ARN whose region segment is empty parses
		// cleanly but must still be rejected by the empty-region guard — a
		// distinct path from the arn.Parse failure above.
		"ValidArnNoRegion_VsockTransport_Errors": {
			cfg: &Config{
				Vsockproxy: Vsockproxy{BasePort: 30000, MaxConns: 4},
				Provider: ProviderConfig{
					AWSKMS: ProviderAWSKMSConfig{Arns: []string{"arn:aws:kms::000000000000:key/test"}},
				},
			},
			opts:            []Option{WithVsockTransport(), WithListen(okListen), WithDial(failingDial)},
			wantErr:         true,
			wantErrContains: "has no region",
		},
	}
	for name, tt := range tests {
		s.Run(name, func() {
			p, err := New(tt.cfg, tt.opts...)
			if tt.wantErr {
				s.Require().Error(err)
				if tt.wantErrContains != "" {
					s.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			s.Require().NoError(err)
			s.Require().NotNil(p)
		})
	}
}

func (s *VsockProxyTestSuite) TestNew_PortMapping() {
	s.Require().NotEmpty(byteproxy.AWSServiceNames)

	var seenPorts []uint32
	listen := func(port uint32) (net.Listener, error) {
		seenPorts = append(seenPorts, port)
		return s.newLocalListener(), nil
	}
	dial := func(_ context.Context, _ string) (net.Conn, error) { return nil, errors.New("dial unused") }

	const base uint32 = 40000
	p, err := New(
		vsockCfg(base, 4),
		WithVsockTransport(), WithListen(listen), WithDial(dial),
	)
	s.Require().NoError(err)
	s.T().Cleanup(func() { _ = p.Shutdown(context.Background()) })

	wantPorts := make([]uint32, len(byteproxy.AWSServiceNames))
	for i := range byteproxy.AWSServiceNames {
		wantPorts[i] = base + uint32(i) //nolint:gosec // bounded by len(AWSServiceNames)
	}
	s.Equal(wantPorts, seenPorts)
	s.Len(seenPorts, len(byteproxy.AWSServiceNames), "listen must be called exactly once per service")
}

func (s *VsockProxyTestSuite) TestNew_EndpointTemplateSubstitution() {
	s.Require().NotEmpty(byteproxy.AWSServiceNames)
	for _, name := range byteproxy.AWSServiceNames {
		tmpl, err := EndpointTemplate(name)
		s.Require().NoError(err)
		s.Contains(tmpl, "{region}")
	}
	const region = "eu-west-2"
	listeners := make([]net.Listener, len(byteproxy.AWSServiceNames))
	for i := range byteproxy.AWSServiceNames {
		listeners[i] = s.newLocalListener()
	}
	idx := 0
	listen := func(_ uint32) (net.Listener, error) {
		ln := listeners[idx]
		idx++
		return ln, nil
	}
	endpointsCh := make(chan string, len(byteproxy.AWSServiceNames))
	dial := func(_ context.Context, endpoint string) (net.Conn, error) {
		endpointsCh <- endpoint
		return nil, errors.New("dial unused")
	}
	p, err := New(
		&Config{
			Vsockproxy: Vsockproxy{BasePort: 40000, MaxConns: 4},
			Provider: ProviderConfig{
				AWSKMS: ProviderAWSKMSConfig{
					Arns: []string{"arn:aws:kms:" + region + ":000000000000:key/abc"},
				},
			},
		},
		WithVsockTransport(), WithListen(listen), WithDial(dial),
	)
	s.Require().NoError(err)
	go func() { _ = p.Run() }()
	s.T().Cleanup(func() { _ = p.Shutdown(context.Background()) })
	for i, ln := range listeners {
		c, derr := net.Dial("tcp", ln.Addr().String())
		s.Require().NoError(derr)
		s.T().Cleanup(func() { _ = c.Close() })
		s.Require().NoError(byteproxy.WriteAWSRoute(c, byteproxy.AWSRoute{
			Service: byteproxy.AWSServiceNames[i],
			Region:  region,
		}))
	}
	seen := make([]string, 0, len(byteproxy.AWSServiceNames))
	for range byteproxy.AWSServiceNames {
		select {
		case ep := <-endpointsCh:
			seen = append(seen, ep)
		case <-time.After(2 * time.Second):
			s.FailNow("timed out waiting for dial to capture endpoint")
		}
	}
	for _, ep := range seen {
		s.NotContains(ep, "{region}")
		s.Contains(ep, region)
		s.True(strings.HasSuffix(ep, ":443"))
	}
}

// TestEnsureServiceParity covers the drift case the function exists to
// catch: a service name listed in byteproxy.AWSServiceNames without a
// corresponding entry in endpointTemplates. The check is fed via
// parameters (rather than the package globals) precisely so this case
// is reachable from tests.
func TestEnsureServiceParity(t *testing.T) {
	tests := map[string]struct {
		services   []string
		templates  map[string]string
		wantErr    bool
		wantErrMsg string
	}{
		"all services covered": {
			services:  []string{"kms"},
			templates: map[string]string{"kms": "kms.{region}.amazonaws.com:443"},
			wantErr:   false,
		},
		"service missing template": {
			services:   []string{"kms", "secretsmanager"},
			templates:  map[string]string{"kms": "kms.{region}.amazonaws.com:443"},
			wantErr:    true,
			wantErrMsg: `"secretsmanager"`,
		},
		"empty services list": {
			services:  nil,
			templates: map[string]string{},
			wantErr:   false,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := ensureServiceParity(tt.services, tt.templates)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErrMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestWithTransport_LastWins verifies that passing both transport options
// is not an error and that the last option applied selects the transport,
// including its TCP upstream endpoint, so the selected kind and its dialer
// stay coherent.
func (s *VsockProxyTestSuite) TestWithTransport_LastWins() {
	s.Run("tcp last", func() {
		o := options{}
		WithVsockTransport()(&o)
		WithTCPTransport()(&o)
		s.Equal(byteproxy.TransportTCP, o.transport)
		s.Equal("localstack:4566", o.tcpLocalstackEndpoint)
	})
	s.Run("vsock last", func() {
		o := options{}
		WithTCPTransport()(&o)
		WithVsockTransport()(&o)
		s.Equal(byteproxy.TransportVsock, o.transport)
	})
}

// TestNew_UnhandledTransportKind covers resolveEndpoint's default guard:
// an out-of-range transport (e.g. a future byteproxy.TransportKind added
// without a matching resolveEndpoint case) must surface an error from New.
// Injected via a raw Option so the guard stays protected from silent
// removal. A non-vsock kind skips region resolution, so no ARN is needed.
func TestNew_UnhandledTransportKind(t *testing.T) {
	badTransport := Option(func(o *options) { o.transport = byteproxy.TransportKind(99) })
	_, err := New(&Config{Vsockproxy: Vsockproxy{BasePort: 30000, MaxConns: 4}}, badTransport)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unhandled transport kind")
}

func TestVsockProxyTestSuite(t *testing.T) {
	suite.Run(t, &VsockProxyTestSuite{Suite: suite.Suite{}})
}
