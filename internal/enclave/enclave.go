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

// Package enclave contains the source code which runs in nitro enclave
package enclave

import (
	"context"
	"sync"

	"github.com/circlefin/arc-remote-signer/internal/common/lifecycle"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/keystore"
	"github.com/circlefin/arc-remote-signer/internal/enclave/public"
	enclaveSvc "github.com/circlefin/arc-remote-signer/internal/enclave/service/enclave"
)

var (
	_logger     *logging.Logger
	_loggerOnce sync.Once
)

func getLogger() *logging.Logger {
	_loggerOnce.Do(func() {
		_logger = logging.Get("nitro-enclave-signer-enclave")
	})
	return _logger
}

// Run runs nitro enclave gRPC server over vsock or tcp.
func Run(cfg *Config) error {
	var ctx = context.Background()
	var err error

	getLogger().Info(ctx, "initializing the providers...", nil)
	var enclavePvd enclave.Provider
	if cfg.NitroEnclave.Enabled {
		enclavePvd, err = enclave.New()
		if err != nil {
			panic(err)
		}
	}

	// Initialize enclave services
	getLogger().Info(ctx, "initializing the services...", nil)
	enclaveService := enclaveSvc.New(cfg.NitroEnclave.Enabled, keystore.New(), enclavePvd)

	// Create server with engine initialization handled in public package
	server, err := public.New(cfg.Public.Server, public.CreateServerParams{
		ServiceName:         cfg.GetName(),
		Env:                 cfg.Env,
		EnclaveService:      enclaveService,
		NitroEnclaveEnabled: cfg.NitroEnclave.Enabled,
	})
	if err != nil {
		getLogger().ErrorErr(ctx, "failed to create server", err, nil)
		panic(err)
	}

	// Create and manage server with lifecycle
	lc := lifecycle.NewManager()
	lc.Manage(server)
	lc.Run()
	return nil
}
