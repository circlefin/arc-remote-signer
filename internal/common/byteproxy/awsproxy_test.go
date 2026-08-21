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
	"net"
	"testing"

	"github.com/stretchr/testify/suite"
)

// AWSProxyTestSuite covers NewAWSProxy's per-service iteration, port
// assignment, binding plumbing, and factory-error propagation. The full
// proxy lifecycle (accept/bridge/shutdown) is covered by ByteProxyTestSuite;
// here we only verify the helper that constructs the per-service Config.
type AWSProxyTestSuite struct {
	suite.Suite
}

// newLocalListener returns a TCP listener bound to a random loopback port.
func (s *AWSProxyTestSuite) newLocalListener() net.Listener {
	s.T().Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	s.Require().NoError(err)
	s.T().Cleanup(func() { _ = ln.Close() })
	return ln
}

// TestNewAWSProxy_PortAssignmentAndIteration verifies that the factory is
// invoked once per AWSServiceNames entry, in order, with port = basePort +
// index. Endpoint, Listen, and Dial flow through to the underlying proxy.
func (s *AWSProxyTestSuite) TestNewAWSProxy_PortAssignmentAndIteration() {
	s.Require().NotEmpty(AWSServiceNames, "AWSServiceNames must declare at least one service")

	const base uint32 = 50000

	var seenNames []string
	var seenPorts []uint32
	bf := func(name string, port uint32) (AWSServiceBinding, error) {
		seenNames = append(seenNames, name)
		seenPorts = append(seenPorts, port)
		return AWSServiceBinding{
			Endpoint: "stub-endpoint",
			Listen:   func() (net.Listener, error) { return s.newLocalListener(), nil },
			Dial:     func(_ context.Context, _ net.Conn) (net.Conn, error) { return nil, errors.New("dial unused") },
		}, nil
	}

	p, err := NewAWSProxy("unit-test", base, 4, bf)
	s.Require().NoError(err)
	s.T().Cleanup(func() { _ = p.Shutdown(context.Background()) })
	s.Equal("unit-test", p.Name())

	wantPorts := make([]uint32, len(AWSServiceNames))
	for i := range AWSServiceNames {
		wantPorts[i] = base + uint32(i) //nolint:gosec // bounded by len(AWSServiceNames)
	}
	s.Equal(AWSServiceNames, seenNames, "factory must be called once per service in order")
	s.Equal(wantPorts, seenPorts, "ports must be basePort + index-in-AWSServiceNames")
}

// TestNewAWSProxy_FactoryError verifies the factory's error is wrapped with
// the service name and surfaced — and that the underlying proxy is not
// constructed (no listeners leak).
func (s *AWSProxyTestSuite) TestNewAWSProxy_FactoryError() {
	s.Require().NotEmpty(AWSServiceNames)

	sentinel := errors.New("binding failed for this test")
	bf := func(_ string, _ uint32) (AWSServiceBinding, error) {
		return AWSServiceBinding{}, sentinel
	}

	p, err := NewAWSProxy("unit-test", 50000, 4, bf)
	s.Require().Error(err)
	s.Require().ErrorIs(err, sentinel)
	s.Contains(err.Error(), AWSServiceNames[0], "error must identify which service's binding failed")
	s.Nil(p)
}

// TestNewAWSProxy_PropagatesNewError verifies that downstream New errors
// (e.g. invalid MaxConns) surface from NewAWSProxy unchanged.
func (s *AWSProxyTestSuite) TestNewAWSProxy_PropagatesNewError() {
	bf := func(_ string, _ uint32) (AWSServiceBinding, error) {
		return AWSServiceBinding{
			Endpoint: "stub",
			Listen:   func() (net.Listener, error) { return s.newLocalListener(), nil },
			Dial:     func(_ context.Context, _ net.Conn) (net.Conn, error) { return nil, errors.New("dial unused") },
		}, nil
	}
	p, err := NewAWSProxy("unit-test", 50000, 0, bf) // MaxConns=0 must fail
	s.Require().Error(err)
	s.Nil(p)
}

// TestAWSProxyTestSuite is the entry point for the suite.
func TestAWSProxyTestSuite(t *testing.T) {
	suite.Run(t, &AWSProxyTestSuite{Suite: suite.Suite{}})
}
