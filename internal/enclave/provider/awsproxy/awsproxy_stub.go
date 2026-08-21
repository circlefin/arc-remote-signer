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

package awsproxy

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
)

// proxyName is the lifecycle.Runnable name reported by the stub; matches
// the Linux build so logs are identical across platforms.
const proxyName = "enclave-awsproxy"

// Provider mirrors the Linux Provider so cross-platform callers compile.
type Provider interface {
	byteproxy.Proxy
}

// New creates an enclave-side proxy. On non-Linux only the TCP transport
// is available; selecting WithVsockTransport is a compile-time error
// because the option lives in the Linux-only transport_vsock.go.
func New(cfg *Config, opts ...Option) (Provider, error) {
	if cfg == nil {
		return nil, errors.New("awsproxy: nil config")
	}
	o := options{}
	for _, apply := range opts {
		apply(&o)
	}
	if o.transport != byteproxy.TransportTCP {
		return nil, errors.New("awsproxy: non-Linux requires WithTCPTransport()")
	}
	p, err := byteproxy.NewAWSProxy(proxyName, cfg.BasePort, cfg.MaxConns,
		func(_ string, port uint32) (byteproxy.AWSServiceBinding, error) {
			endpoint := fmt.Sprintf("tcp %s:%d", o.tcpParentHost, port)
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
