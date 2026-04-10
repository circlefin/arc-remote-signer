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

package lifecycle

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	// shutdownTimeout is the maximum time to wait for graceful shutdown.
	shutdownTimeout = 30 * time.Second
)

// Manager manages a set of Runnable services.
type Manager struct {
	runnables []Runnable
}

// NewManager creates a new lifecycle manager.
func NewManager() *Manager {
	return &Manager{
		runnables: make([]Runnable, 0),
	}
}

// Manage adds a Runnable to be managed by this lifecycle.
func (m *Manager) Manage(r Runnable) {
	m.runnables = append(m.runnables, r)
}

// Run starts all managed runnables and waits for shutdown signal.
func (m *Manager) Run() {
	// Start all runnables
	for _, r := range m.runnables {
		if err := r.Run(); err != nil {
			log.Fatalf("failed to start runnable: %v", err)
		}
	}

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down...")

	// Shutdown all runnables with timeout
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, r := range m.runnables {
		if err := r.Shutdown(ctx); err != nil {
			log.Printf("failed to shutdown runnable: %v", err)
		}
	}
}
