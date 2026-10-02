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
	"fmt"
	"net"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
)

// proxyName is the lifecycle.Runnable name reported by both the enabled
// and disabled providers.
const proxyName = "host-vsockproxy"

// Provider is the host-side proxy interface (byteproxy.Proxy plus the
// dropped-count observability hook).
type Provider interface {
	byteproxy.Proxy
}

// New creates a host-side proxy. The transport defaults to vsock (the
// zero value); pass WithTCPTransport() to select TCP for dev/CI.
// Passing both transport options is allowed and the last one wins.
func New(cfg *Config, opts ...Option) (Provider, error) {
	if cfg == nil {
		return nil, errors.New("vsockproxy: nil config")
	}

	// transport's zero value is vsock; start with its listen/dial so a call
	// with no transport option runs vsock. A transport option overrides both.
	o := options{listen: vsockListen, dial: vsockDial}
	for _, apply := range opts {
		apply(&o)
	}

	resolver, err := newRouteResolver(cfg, &o)
	if err != nil {
		return nil, err
	}

	p, err := byteproxy.NewAWSProxy(proxyName, cfg.Vsockproxy.BasePort, cfg.Vsockproxy.MaxConns,
		func(svc string, port uint32) (byteproxy.AWSServiceBinding, error) {
			// Endpoint is informational only (byteproxy logs it). In vsock mode
			// the real kms.<region>.amazonaws.com:443 target is resolved per
			// connection in resolver.dial from the AWSRoute header, so record a
			// descriptor here rather than the unresolved "{region}" template.
			var endpoint string
			if cfg.Provider.AWSKMS.Localstack.Enabled {
				endpoint = o.tcpLocalstackEndpoint
			} else {
				endpoint = svc + " (region resolved per connection)"
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
