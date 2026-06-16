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

package metric

import (
	grpcprom "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Prometheus bundles a dedicated Prometheus registry with gRPC server metrics
// produced by the go-grpc-middleware provider. Instrumentation is centralized
// in a unary interceptor rather than hand-rolled per-handler counters.
type Prometheus struct {
	registry      *prometheus.Registry
	serverMetrics *grpcprom.ServerMetrics
}

// NewPrometheus creates a Prometheus provider with gRPC server metrics (request
// totals by method and status code plus a handling-time histogram) and Go
// runtime and process collectors registered on a dedicated registry.
func NewPrometheus() *Prometheus {
	serverMetrics := grpcprom.NewServerMetrics(
		grpcprom.WithServerHandlingTimeHistogram(),
	)

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		serverMetrics,
	)

	return &Prometheus{
		registry:      registry,
		serverMetrics: serverMetrics,
	}
}

// Registry returns the Prometheus registry backing this provider.
func (p *Prometheus) Registry() *prometheus.Registry {
	return p.registry
}

// UnaryServerInterceptor returns the gRPC unary interceptor that records server
// metrics for each RPC.
func (p *Prometheus) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return p.serverMetrics.UnaryServerInterceptor()
}

// InitializeMetrics pre-registers metrics for every method the given server
// exposes so counters start at zero before the first request is served.
func (p *Prometheus) InitializeMetrics(server reflection.ServiceInfoProvider) {
	p.serverMetrics.InitializeMetrics(server)
}
