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

package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/circlefin/arc-remote-signer/internal/common/lifecycle"
)

// RunnableImpl manages http server lifecycle and implements lifecycle.Runnable.
type RunnableImpl struct {
	server            *http.Server
	name              string
	listener          net.Listener
	beforeShutdownFns []func()
}

// NewRunnable creates a runnable wrapper around a http.Server.
func NewRunnable(name string, server *http.Server, opts ...RunnableOption) (lifecycle.Runnable, error) {
	r := &RunnableImpl{
		server: server,
		name:   name,
	}
	for _, opt := range opts {
		if err := opt(r); err != nil {
			return nil, err
		}
	}
	if r.listener == nil {
		return nil, fmt.Errorf("failed to initialize runnable http server: listener is not configured")
	}
	return r, nil
}

// Addr returns the listener address when available.
func (s *RunnableImpl) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Run starts the http server in a goroutine.
func (s *RunnableImpl) Run() error {
	go func() {
		log.Printf("http server listening on %s", s.listener.Addr().String())
		if err := s.server.Serve(s.listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("failed to serve: %v", err)
		}
	}()
	return nil
}

// Shutdown gracefully stops the http server.
func (s *RunnableImpl) Shutdown(ctx context.Context) error {
	for _, fn := range s.beforeShutdownFns {
		fn()
	}
	addr := "unknown"
	if s.listener != nil {
		addr = s.listener.Addr().String()
	}
	log.Printf("initiating graceful shutdown of http server at %s", addr)

	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown http server: %w", err)
	}
	log.Printf("http server gracefully stopped")
	return nil
}

// Name returns the configured service name.
func (s *RunnableImpl) Name() string {
	return s.name
}
