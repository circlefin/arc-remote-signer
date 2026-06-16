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

// Package metrics provides the Prometheus metrics HTTP server for the app service.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/circlefin/arc-remote-signer/internal/common/lifecycle"
	"github.com/circlefin/arc-remote-signer/internal/common/metric"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// serverName identifies the metrics runnable within the lifecycle manager.
const serverName = "metrics"

// Server serves Prometheus metrics over HTTP and implements lifecycle.Runnable.
type Server struct {
	server   *http.Server
	listener net.Listener
}

// New creates a metrics server runnable that serves the provider's registry on
// the configured endpoint. It returns (nil, nil) when Prometheus metrics are
// disabled so callers can skip managing it.
func New(cfg *metric.Config, prometheus *metric.Prometheus) (_ lifecycle.Runnable, err error) {
	// http.ServeMux.Handle panics on an invalid pattern (Go 1.22+), and the set of
	// invalid patterns is broader than any simple pre-check can cover, so recover
	// and surface a config error instead of letting a bad path crash startup.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("invalid metrics configuration: %v", r)
		}
	}()

	if cfg == nil || !cfg.IsPrometheusEnabled() {
		return nil, nil
	}
	if prometheus == nil {
		return nil, fmt.Errorf("prometheus provider is not initialized")
	}

	// Register before opening the listener so a bad path fails without leaking a socket.
	mux := http.NewServeMux()
	mux.Handle(cfg.Prometheus.GetPath(), promhttp.HandlerFor(prometheus.Registry(), promhttp.HandlerOpts{}))

	addr := cfg.Prometheus.GetAddr()
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics listener on %s: %w", addr, err)
	}

	return &Server{
		server: &http.Server{
			Handler: mux,
			// Bound every phase so the optional metrics endpoint cannot hold
			// resources indefinitely (ReadHeaderTimeout also mitigates Slowloris).
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
		listener: listener,
	}, nil
}

// Run starts the metrics HTTP server in a goroutine. It implements lifecycle.Runnable.
func (s *Server) Run() error {
	go func() {
		log.Printf("metrics server listening on %s", s.listener.Addr().String())
		if err := s.server.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Metrics is an optional, non-critical endpoint: log and stop serving
			// metrics rather than aborting the whole signer process.
			log.Printf("metrics server stopped serving: %v", err)
		}
	}()
	return nil
}

// Shutdown gracefully stops the metrics HTTP server. It implements lifecycle.Runnable.
func (s *Server) Shutdown(ctx context.Context) error {
	log.Printf("initiating graceful shutdown of metrics server")
	return s.server.Shutdown(ctx)
}

// Name returns the metrics server name. It implements lifecycle.Runnable.
func (s *Server) Name() string {
	return serverName
}
