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

//go:build !linux

package vsockproxy

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
)

// proxyName is the lifecycle.Runnable name reported by the stub; matches
// the Linux build so logs are identical across platforms.
const proxyName = "host-vsockproxy"

// Provider mirrors the Linux Provider so cross-platform callers compile.
type Provider interface {
	byteproxy.Proxy
}

// New creates a host-side proxy. On non-Linux only the TCP transport is
// available; selecting WithVsockTransport is a compile-time error
// because the option lives in the Linux-only transport_vsock.go.
func New(cfg *Config, opts ...Option) (Provider, error) {
	if cfg == nil {
		return nil, errors.New("vsockproxy: nil config")
	}
	o := options{}
	for _, apply := range opts {
		apply(&o)
	}
	if o.transport != byteproxy.TransportTCP {
		return nil, errors.New("vsockproxy: non-Linux requires WithTCPTransport()")
	}
	resolver, err := newRouteResolver(cfg, &o)
	if err != nil {
		return nil, err
	}
	p, err := byteproxy.NewAWSProxy(proxyName, cfg.Vsockproxy.BasePort, cfg.Vsockproxy.MaxConns,
		func(svc string, port uint32) (byteproxy.AWSServiceBinding, error) {
			endpoint := svc + " (region resolved per connection)"
			if cfg.Provider.AWSKMS.Localstack.Enabled {
				endpoint = o.tcpLocalstackEndpoint
			}
			return byteproxy.AWSServiceBinding{
				Endpoint: endpoint,
				Listen:   func() (net.Listener, error) { return o.listen(port) },
				Dial: func(ctx context.Context, inbound net.Conn) (net.Conn, error) {
					return resolver.dial(ctx, svc, inbound)
				},
			}, nil
		})
	if err != nil {
		return nil, fmt.Errorf("vsockproxy: %w", err)
	}
	return p, nil
}
