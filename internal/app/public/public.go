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

// Package public provides the public server of the app service.
package public

import (
	"fmt"

	"github.com/circlefin/arc-remote-signer/internal/common/config"
	grpcServer "github.com/circlefin/arc-remote-signer/internal/common/grpc/server"
	"github.com/circlefin/arc-remote-signer/internal/common/lifecycle"
	"github.com/circlefin/arc-remote-signer/internal/common/metric"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"google.golang.org/grpc/reflection"
)

// CreateServerParams is a param struct passed in to create a new public server.
type CreateServerParams struct {
	ServiceName string
	Env         config.Environment
	APIStatsSvc metric.APIStatsService
	SignerSvc   pb.SignerServiceServer
	// Prometheus, when set, installs the gRPC server metrics interceptor and
	// pre-initializes per-method metrics. It is nil when metrics are disabled.
	Prometheus *metric.Prometheus
}

// New creates a new public server that implements lifecycle.Runnable for the app service.
func New(cfg *grpcServer.Config, params CreateServerParams) (lifecycle.Runnable, error) {
	opts, err := grpcServer.WithTLS(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS options: %w", err)
	}

	engineParams := grpcServer.RequiredEngineParams{
		ServiceName:     params.ServiceName,
		Env:             params.Env,
		APIStatsService: params.APIStatsSvc,
	}
	if params.Prometheus != nil {
		engineParams.UnaryInterceptors = append(engineParams.UnaryInterceptors, params.Prometheus.UnaryServerInterceptor())
	}

	grpcSrv := grpcServer.NewServer(engineParams, opts...)
	reflection.Register(grpcSrv)
	pb.RegisterSignerServiceServer(grpcSrv, params.SignerSvc)

	runnable, err := grpcServer.NewRunnable(
		params.ServiceName,
		grpcSrv,
		grpcServer.WithListener(grpcServer.ListenerTransportTCP, cfg.Host, uint32(cfg.Port)),
		grpcServer.WithHealthServer(pb.SignerService_ServiceDesc.ServiceName),
	)
	if err != nil {
		return nil, err
	}

	// Pre-seed metrics after all services are registered — WithHealthServer adds
	// grpc.health.v1 inside NewRunnable, so doing this earlier would miss its RPCs.
	if params.Prometheus != nil {
		params.Prometheus.InitializeMetrics(grpcSrv)
	}

	return runnable, nil
}
