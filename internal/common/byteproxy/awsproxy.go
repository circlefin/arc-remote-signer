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

import "fmt"

// AWSServiceBinding is what a wrapper supplies per service: an informational
// Endpoint (logged on dial failure) plus the Listen and Dial closures that
// the framework will invoke. Wrappers close over the port and any other
// transport-specific state when constructing the binding.
type AWSServiceBinding struct {
	Endpoint string
	Listen   ListenFunc
	Dial     DialFunc
}

// BindingFactory is the wrapper-supplied callback that produces one binding
// per service. NewAWSProxy iterates AWSServiceNames and calls this for each
// (name, port) pair. Returning an error aborts construction.
type BindingFactory func(name string, port uint32) (AWSServiceBinding, error)

// NewAWSProxy builds a Proxy over AWSServiceNames by asking the wrapper for
// one binding per service. Wrappers (awsproxy on the enclave, vsockproxy on
// the host) share this so the services loop, port assignment, and Config
// assembly cannot drift between the two sides of the bridge.
//
// Ports are assigned as basePort + index-in-AWSServiceNames, matching the
// hand-rolled implementations that this helper replaces.
func NewAWSProxy(name string, basePort uint32, maxConns int, bf BindingFactory) (Proxy, error) {
	services := make([]ServiceConfig, 0, len(AWSServiceNames))
	for i, svc := range AWSServiceNames {
		port := basePort + uint32(i) //nolint:gosec // bounded by len(AWSServiceNames)
		b, err := bf(svc, port)
		if err != nil {
			return nil, fmt.Errorf("byteproxy: binding for service %q: %w", svc, err)
		}
		services = append(services, ServiceConfig{
			Name:     svc,
			Endpoint: b.Endpoint,
			Listen:   b.Listen,
			Dial:     b.Dial,
		})
	}
	return New(&Config{Name: name, Services: services, MaxConns: maxConns})
}
