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

package metrics

import (
	"fmt"
	"log"
	"net/http"

	"github.com/circlefin/arc-remote-signer/internal/common/http/server"
	"github.com/circlefin/arc-remote-signer/internal/common/lifecycle"
	"github.com/circlefin/arc-remote-signer/internal/common/metric"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// New creates a new metrics server that implements lifecycle.Runnable.
func New(cfg *metric.Config, prometheus *metric.Prometheus) (lifecycle.Runnable, error) {
	if cfg == nil || cfg.Prometheus == nil || !cfg.Prometheus.Enabled {
		return nil, nil
	}

	if prometheus == nil {
		return nil, fmt.Errorf("prometheus is not initialized")
	}

	// register metrics
	log.Printf("registering metrics...")
	for _, metric := range metrics {
		prometheus.Register(metric)
	}

	promHandler := promhttp.InstrumentMetricHandler(prometheus.Registry(), promhttp.HandlerFor(prometheus.Registry(), promhttp.HandlerOpts{}))
	path := cfg.Prometheus.GetPath()
	mux := http.NewServeMux()
	mux.Handle(path, promHandler)

	metricsServer := server.NewServer(server.RequiredEngineParams{
		ServerName: "metrics",
	}, mux)
	return server.NewRunnable("metrics", metricsServer, server.WithListener(cfg.Prometheus.Host, cfg.Prometheus.Port))
}
