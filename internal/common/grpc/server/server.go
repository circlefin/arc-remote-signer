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

// Package server provides a default server for grpc services.
package server

import (
	"github.com/circlefin/arc-remote-signer/internal/common/config"
	"github.com/circlefin/arc-remote-signer/internal/common/grpc/server/interceptor"
	"github.com/circlefin/arc-remote-signer/internal/common/metric"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
)

// RequiredEngineParams defines required params for shared grpc server creation.
type RequiredEngineParams struct {
	ServiceName       string
	Env               config.Environment
	APIStatsService   metric.APIStatsService
	UnaryInterceptors []grpc.UnaryServerInterceptor
}

// NewServer creates a grpc.Server with default middleware and options.
func NewServer(params RequiredEngineParams, opts ...grpc.ServerOption) *grpc.Server {
	unaryInterceptors := []grpc.UnaryServerInterceptor{
		interceptor.WithRecovery(),
		interceptor.WithRequestID(),
		interceptor.WithMetrics(params.APIStatsService),
		interceptor.WithLogging(),
	}
	unaryInterceptors = append(unaryInterceptors, params.UnaryInterceptors...)

	opts = append(opts, []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
	}...)

	return grpc.NewServer(opts...)
}
