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
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
)

const routeReadTimeout = time.Second

type routeResolver struct {
	allowedRegions map[string]struct{}
	useLocalstack  bool
	options        *options
}

func newRouteResolver(cfg *Config, o *options) (*routeResolver, error) {
	if cfg == nil {
		return nil, errors.New("vsockproxy: nil config")
	}
	if err := ensureServiceParity(byteproxy.AWSServiceNames, endpointTemplates); err != nil {
		return nil, err
	}
	if o.transport != byteproxy.TransportVsock && o.transport != byteproxy.TransportTCP {
		return nil, fmt.Errorf("vsockproxy: unhandled transport kind %d", o.transport)
	}
	if cfg.Provider.AWSKMS.Localstack.Enabled {
		if o.transport != byteproxy.TransportTCP {
			return nil, errors.New("vsockproxy: LocalStack requires TCP transport")
		}
		return &routeResolver{useLocalstack: true, options: o}, nil
	}
	if len(cfg.Provider.AWSKMS.Arns) == 0 {
		return nil, errors.New("vsockproxy: provider.awskms.arns has no entry to derive allowed regions from")
	}
	regions := make(map[string]struct{}, len(cfg.Provider.AWSKMS.Arns))
	for i, value := range cfg.Provider.AWSKMS.Arns {
		parsed, err := arn.Parse(value)
		if err != nil {
			return nil, fmt.Errorf("vsockproxy: provider.awskms.arns[%d] is not a valid ARN: %w", i, err)
		}
		if parsed.Service != "kms" {
			return nil, fmt.Errorf("vsockproxy: provider.awskms.arns[%d] is not a KMS ARN", i)
		}
		if parsed.Region == "" {
			return nil, fmt.Errorf("vsockproxy: provider.awskms.arns[%d] has no region", i)
		}
		regions[parsed.Region] = struct{}{}
	}
	return &routeResolver{allowedRegions: regions, options: o}, nil
}

func (r *routeResolver) resolve(route byteproxy.AWSRoute) (string, error) {
	tmpl, ok := endpointTemplates[route.Service]
	if !ok {
		return "", fmt.Errorf("vsockproxy: route service %q is not supported", route.Service)
	}
	if r.useLocalstack {
		return r.options.tcpLocalstackEndpoint, nil
	}
	if _, ok := r.allowedRegions[route.Region]; !ok {
		return "", fmt.Errorf("vsockproxy: route region %q is not configured", route.Region)
	}
	return strings.ReplaceAll(tmpl, "{region}", route.Region), nil
}

func (r *routeResolver) dial(
	ctx context.Context,
	service string,
	inbound net.Conn,
) (net.Conn, error) {
	route, err := r.readRoute(ctx, inbound)
	if err != nil {
		return nil, err
	}
	if route.Service != service {
		return nil, fmt.Errorf("vsockproxy: route service %q does not match listener service %q", route.Service, service)
	}
	endpoint, err := r.resolve(route)
	if err != nil {
		return nil, err
	}
	upstream, err := r.options.dial(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("vsockproxy: dial %s: %w", endpoint, err)
	}
	return upstream, nil
}

// readRoute reads exactly one AWS route header from inbound, bounded by both
// routeReadTimeout and ctx cancellation. bridge passes the shutdown ctx so a
// connection stalled mid-header does not delay Shutdown past a ctx cancel:
// on cancellation the pending read is unblocked (deadline moved to now) and
// the reader goroutine is reaped before returning.
func (r *routeResolver) readRoute(ctx context.Context, inbound net.Conn) (byteproxy.AWSRoute, error) {
	if err := inbound.SetReadDeadline(time.Now().Add(routeReadTimeout)); err != nil {
		return byteproxy.AWSRoute{}, fmt.Errorf("vsockproxy: set route read deadline: %w", err)
	}
	type result struct {
		route byteproxy.AWSRoute
		err   error
	}
	resultCh := make(chan result, 1)
	go func() {
		route, err := byteproxy.ReadAWSRoute(inbound)
		resultCh <- result{route: route, err: err}
	}()

	select {
	case <-ctx.Done():
		// Force the blocked ReadAWSRoute to return so the goroutine exits, then
		// reap it to avoid a leak before reporting the cancellation.
		_ = inbound.SetReadDeadline(time.Now())
		<-resultCh
		return byteproxy.AWSRoute{}, fmt.Errorf("vsockproxy: route read cancelled: %w", ctx.Err())
	case res := <-resultCh:
		if resetErr := inbound.SetReadDeadline(time.Time{}); resetErr != nil && res.err == nil {
			return byteproxy.AWSRoute{}, fmt.Errorf("vsockproxy: clear route read deadline: %w", resetErr)
		}
		if res.err != nil {
			return byteproxy.AWSRoute{}, fmt.Errorf("vsockproxy: read route: %w", res.err)
		}
		return res.route, nil
	}
}

func ensureServiceParity(services []string, templates map[string]string) error {
	for _, name := range services {
		if _, ok := templates[name]; !ok {
			return fmt.Errorf(
				"vsockproxy: byteproxy.AWSServiceNames includes %q but no endpoint template is registered; "+
					"add an entry to vsockproxy/config.go endpointTemplates", name,
			)
		}
	}
	return nil
}
