//go:build !linux

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
	"time"

	"github.com/circlefin/arc-remote-signer/internal/common/lifecycle"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
)

// errVsockRequiresLinux is returned by Run when vsock transport is
// requested on a non-Linux build, where it cannot be satisfied.
var errVsockRequiresLinux = errors.New("vsockproxy: vsock transport requires Linux")

// Run constructs the vsockproxy on non-Linux platforms. Only TCP
// transport is available, so Run rejects NitroEnclave.Enabled up front;
// WithVsockTransport does not exist in non-Linux builds.
func Run(cfg *Config) error {
	if cfg.Provider.Enclave.NitroEnclave.Enabled {
		return errVsockRequiresLinux
	}

	logger := logging.Get(configName)
	logger.Info(context.Background(), "starting vsockproxy (non-Linux, TCP only)", logging.Entries{
		"basePort": cfg.Vsockproxy.BasePort,
	})

	p, err := New(cfg, transportOptionForConfig(cfg))
	if err != nil {
		return err
	}
	// Release the listeners New bound on every post-construction return path
	// (e.g. a signalReady failure below). Shutdown is idempotent, so the
	// lifecycle-driven shutdown after Run still works on the happy path; the
	// bounded context caps this cleanup so it cannot outlive the lifecycle's
	// own shutdown budget.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	}()

	// Listeners are bound by New (see byteproxy.New), so signal readiness
	// now — before blocking on Run — to let the parent gate enclave startup
	// on the proxy actually listening.
	if err := signalReady(); err != nil {
		return err
	}

	lc := lifecycle.NewManager()
	lc.Manage(p)
	lc.Run()
	return nil
}

// transportOptionForConfig on non-Linux always returns WithTCPTransport;
// vsock mode is rejected earlier in Run because WithVsockTransport does
// not exist in non-Linux builds.
func transportOptionForConfig(_ *Config) Option {
	return WithTCPTransport()
}
