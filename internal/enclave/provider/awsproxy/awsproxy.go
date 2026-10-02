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
	"fmt"
	"net"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
)

// proxyName is the lifecycle.Runnable name reported by both the enabled
// and disabled providers.
const proxyName = "enclave-awsproxy"

// Provider exposes the proxy as a byteproxy.Proxy so the enclave's
// lifecycle.Manager can supervise it alongside the gRPC server.
type Provider interface {
	byteproxy.Proxy
}

// New creates an enclave-side proxy. The transport defaults to vsock (the
// zero value); pass WithTCPTransport() to select TCP for dev/CI. Passing
// both transport options is allowed and the last one wins.
func New(cfg *Config, opts ...Option) (Provider, error) {
	if cfg == nil {
		return nil, errors.New("awsproxy: nil config")
	}
	// transport's zero value is vsock; start with its listen/dial so a call
	// with no transport option runs vsock. A transport option overrides both.
	o := options{listen: vsockTransportListen, dial: vsockTransportDial}
	for _, apply := range opts {
		apply(&o)
	}

	p, err := byteproxy.NewAWSProxy(proxyName, cfg.BasePort, cfg.MaxConns,
		func(_ string, port uint32) (byteproxy.AWSServiceBinding, error) {
			endpoint, err := describeEndpoint(&o, port)
			if err != nil {
				return byteproxy.AWSServiceBinding{}, err
			}
			return byteproxy.AWSServiceBinding{
				Endpoint: endpoint,
				Listen:   func() (net.Listener, error) { return o.listen(port) },
				Dial:     func(ctx context.Context, _ net.Conn) (net.Conn, error) { return o.dial(ctx, port) },
			}, nil
		})
	if err != nil {
		return nil, fmt.Errorf("awsproxy: %w", err)
	}
	return p, nil
}

// describeEndpoint produces the informational upstream string logged by
// byteproxy on dial failure. Both transports dial port-based; only the
// host part differs. The default branch guards against a future transport
// kind added without a matching case, surfacing it rather than silently
// logging an empty endpoint.
func describeEndpoint(o *options, port uint32) (string, error) {
	switch o.transport {
	case byteproxy.TransportVsock:
		return fmt.Sprintf("vsock CID=%d:%d", parentCID, port), nil
	case byteproxy.TransportTCP:
		return fmt.Sprintf("tcp %s:%d", o.tcpParentHost, port), nil
	default:
		return "", fmt.Errorf("awsproxy: unhandled transport kind %d", o.transport)
	}
}
