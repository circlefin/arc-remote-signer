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
	"errors"
	"net"
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
	"github.com/stretchr/testify/require"
)

func TestRouteResolverSelectsRequestedAllowedRegion(t *testing.T) {
	cfg := &Config{Provider: ProviderConfig{AWSKMS: ProviderAWSKMSConfig{Arns: []string{
		"arn:aws:kms:us-east-1:123456789012:key/first",
		"arn:aws:kms:us-west-2:123456789012:key/second",
	}}}}
	resolver, err := newRouteResolver(cfg, &options{transport: byteproxy.TransportVsock})
	require.NoError(t, err)

	endpoint, err := resolver.resolve(byteproxy.AWSRoute{Service: "kms", Region: "us-west-2"})
	require.NoError(t, err)
	require.Equal(t, "kms.us-west-2.amazonaws.com:443", endpoint)
}

func TestRouteResolverSelectsBackendInTCPMode(t *testing.T) {
	tests := map[string]struct {
		localstack bool
		want       string
	}{
		"LocalStack": {localstack: true, want: "localstack:4566"},
		"AWS KMS":    {want: "kms.us-west-2.amazonaws.com:443"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := &Config{Provider: ProviderConfig{AWSKMS: ProviderAWSKMSConfig{
				Arns: []string{"arn:aws:kms:us-west-2:123456789012:key/test"},
				Localstack: ProviderAWSKMSLocalstackConfig{
					Enabled: tt.localstack,
				},
			}}}
			resolver, err := newRouteResolver(cfg, &options{
				transport:             byteproxy.TransportTCP,
				tcpLocalstackEndpoint: "localstack:4566",
			})
			require.NoError(t, err)

			endpoint, err := resolver.resolve(byteproxy.AWSRoute{Service: "kms", Region: "us-west-2"})
			require.NoError(t, err)
			require.Equal(t, tt.want, endpoint)
		})
	}
}

func TestRouteResolverUsesConfiguredLocalstackTarget(t *testing.T) {
	cfg := &Config{Provider: ProviderConfig{AWSKMS: ProviderAWSKMSConfig{
		Localstack: ProviderAWSKMSLocalstackConfig{Enabled: true},
	}}}
	resolver, err := newRouteResolver(cfg, &options{
		transport:             byteproxy.TransportTCP,
		tcpLocalstackEndpoint: "test-localstack:4566",
	})
	require.NoError(t, err)

	endpoint, err := resolver.resolve(byteproxy.AWSRoute{Service: "kms", Region: "us-east-1"})
	require.NoError(t, err)
	require.Equal(t, "test-localstack:4566", endpoint)
}

func TestRouteResolverRejectsLocalstackWithVsock(t *testing.T) {
	cfg := &Config{Provider: ProviderConfig{AWSKMS: ProviderAWSKMSConfig{
		Localstack: ProviderAWSKMSLocalstackConfig{Enabled: true},
	}}}

	_, err := newRouteResolver(cfg, &options{transport: byteproxy.TransportVsock})
	require.ErrorContains(t, err, "LocalStack requires TCP transport")
}

func TestRouteResolverRejectsRegionOutsideARNAllowlist(t *testing.T) {
	cfg := &Config{Provider: ProviderConfig{AWSKMS: ProviderAWSKMSConfig{Arns: []string{
		"arn:aws:kms:us-east-1:123456789012:key/first",
	}}}}
	resolver, err := newRouteResolver(cfg, &options{transport: byteproxy.TransportVsock})
	require.NoError(t, err)

	_, err = resolver.resolve(byteproxy.AWSRoute{Service: "kms", Region: "eu-west-1"})
	require.ErrorContains(t, err, "not configured")
}

func TestRouteResolverRejectsServiceMismatch(t *testing.T) {
	cfg := &Config{Provider: ProviderConfig{AWSKMS: ProviderAWSKMSConfig{Arns: []string{
		"arn:aws:kms:us-east-1:123456789012:key/first",
	}}}}
	resolver, err := newRouteResolver(cfg, &options{transport: byteproxy.TransportVsock})
	require.NoError(t, err)

	_, err = resolver.resolve(byteproxy.AWSRoute{Service: "secretsmanager", Region: "us-east-1"})
	require.ErrorContains(t, err, "service")
}

func TestRouteResolverDialReadsInboundRoute(t *testing.T) {
	client, inbound := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = inbound.Close() })
	upstream, upstreamPeer := net.Pipe()
	t.Cleanup(func() { _ = upstream.Close() })
	t.Cleanup(func() { _ = upstreamPeer.Close() })

	dialed := make(chan string, 1)
	cfg := &Config{Provider: ProviderConfig{AWSKMS: ProviderAWSKMSConfig{Arns: []string{
		"arn:aws:kms:us-east-1:123456789012:key/first",
		"arn:aws:kms:us-west-2:123456789012:key/second",
	}}}}
	resolver, err := newRouteResolver(cfg, &options{
		transport: byteproxy.TransportVsock,
		dial: func(_ context.Context, endpoint string) (net.Conn, error) {
			dialed <- endpoint
			return upstream, nil
		},
	})
	require.NoError(t, err)

	writeErr := make(chan error, 1)
	go func() {
		writeErr <- byteproxy.WriteAWSRoute(client, byteproxy.AWSRoute{
			Service: "kms",
			Region:  "us-west-2",
		})
	}()
	gotConn, err := resolver.dial(context.Background(), "kms", inbound)
	require.NoError(t, err)
	require.Same(t, upstream, gotConn)
	require.NoError(t, <-writeErr)
	require.Equal(t, "kms.us-west-2.amazonaws.com:443", <-dialed)
}

func TestRouteResolverDialErrorIncludesResolvedEndpoint(t *testing.T) {
	client, inbound := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = inbound.Close() })

	cfg := &Config{Provider: ProviderConfig{AWSKMS: ProviderAWSKMSConfig{Arns: []string{
		"arn:aws:kms:us-west-2:123456789012:key/second",
	}}}}
	resolver, err := newRouteResolver(cfg, &options{
		transport: byteproxy.TransportVsock,
		dial: func(_ context.Context, _ string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		},
	})
	require.NoError(t, err)

	writeErr := make(chan error, 1)
	go func() {
		writeErr <- byteproxy.WriteAWSRoute(client, byteproxy.AWSRoute{
			Service: "kms",
			Region:  "us-west-2",
		})
	}()
	_, err = resolver.dial(context.Background(), "kms", inbound)
	require.ErrorContains(t, err, "kms.us-west-2.amazonaws.com:443")
	require.NoError(t, <-writeErr)
}

func TestRouteResolverDialRejectsServiceMismatch(t *testing.T) {
	client, inbound := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = inbound.Close() })

	cfg := &Config{Provider: ProviderConfig{AWSKMS: ProviderAWSKMSConfig{Arns: []string{
		"arn:aws:kms:us-east-1:123456789012:key/first",
	}}}}
	resolver, err := newRouteResolver(cfg, &options{
		transport: byteproxy.TransportVsock,
		dial: func(_ context.Context, _ string) (net.Conn, error) {
			return nil, errors.New("dial must not be reached on service mismatch")
		},
	})
	require.NoError(t, err)

	// The inbound route declares a service other than the listener's ("kms"),
	// so dial must reject it before resolving an endpoint or dialing upstream.
	writeErr := make(chan error, 1)
	go func() {
		writeErr <- byteproxy.WriteAWSRoute(client, byteproxy.AWSRoute{
			Service: "secretsmanager",
			Region:  "us-east-1",
		})
	}()
	_, err = resolver.dial(context.Background(), "kms", inbound)
	require.ErrorContains(t, err, "does not match listener service")
	require.NoError(t, <-writeErr)
}

func TestRouteResolverDialCancelsRouteReadOnContext(t *testing.T) {
	client, inbound := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = inbound.Close() })

	cfg := &Config{Provider: ProviderConfig{AWSKMS: ProviderAWSKMSConfig{Arns: []string{
		"arn:aws:kms:us-east-1:123456789012:key/first",
	}}}}
	resolver, err := newRouteResolver(cfg, &options{
		transport: byteproxy.TransportVsock,
		dial: func(_ context.Context, _ string) (net.Conn, error) {
			return nil, errors.New("dial must not be reached when the route read is cancelled")
		},
	})
	require.NoError(t, err)

	// No route is ever written to client, so the header read blocks; a cancelled
	// ctx must abort it (well before the 1s routeReadTimeout) rather than hang.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = resolver.dial(ctx, "kms", inbound)
	require.ErrorIs(t, err, context.Canceled)
}
