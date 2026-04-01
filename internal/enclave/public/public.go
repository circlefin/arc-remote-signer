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

// Package public provides the public server of the enclave service.
package public

import (
	"fmt"

	"buf.build/go/protovalidate"
	"github.com/circlefin/arc-remote-signer/internal/common/config"
	grpcserver "github.com/circlefin/arc-remote-signer/internal/common/grpc/server"
	"github.com/circlefin/arc-remote-signer/internal/common/lifecycle"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	protovalidatemw "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/protovalidate"
	"google.golang.org/grpc"
)

// CreateServerParams is a param struct passed in to create a new public server.
type CreateServerParams struct {
	ServiceName         string
	Env                 config.Environment
	EnclaveService      pb.EnclaveServiceServer
	NitroEnclaveEnabled bool
}

// New creates a new public server that implements lifecycle.Runnable for the app service.
func New(cfg *grpcserver.Config, params CreateServerParams) (lifecycle.Runnable, error) {
	validator, err := protovalidate.New()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize protovalidate: %w", err)
	}

	grpcServer := grpcserver.NewServer(grpcserver.RequiredEngineParams{
		ServiceName:     params.ServiceName,
		Env:             params.Env,
		APIStatsService: nil,
		UnaryInterceptors: []grpc.UnaryServerInterceptor{
			protovalidatemw.UnaryServerInterceptor(validator),
		},
	})
	pb.RegisterEnclaveServiceServer(grpcServer, params.EnclaveService)

	transport := grpcserver.ListenerTransportTCP
	if params.NitroEnclaveEnabled {
		transport = grpcserver.ListenerTransportVSOCK
	}

	return grpcserver.NewRunnable(
		params.ServiceName,
		grpcServer,
		grpcserver.WithListener(transport, cfg.Host, uint32(cfg.Port)),
		grpcserver.WithHealthServer(pb.EnclaveService_ServiceDesc.ServiceName),
	)
}
