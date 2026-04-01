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

//go:generate mockgen -source=runnable.go -destination=runnable_mock.go -package=lifecycle

// Package lifecycle provides common service lifecycle management types.
package lifecycle

import "context"

// Runnable defines a service that can be started and stopped.
type Runnable interface {
	// Run starts the service.
	Run() error
	// Shutdown gracefully stops the service.
	Shutdown(ctx context.Context) error
	// Name returns the service name.
	Name() string
}
