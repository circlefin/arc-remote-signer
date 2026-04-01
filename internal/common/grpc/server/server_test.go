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
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpcHealth "google.golang.org/grpc/health"
	grpcHealthV1 "google.golang.org/grpc/health/grpc_health_v1"
)

func TestNewServer_AppliesCustomUnaryInterceptors(t *testing.T) {
	var interceptorCalled atomic.Bool
	customInterceptor := func(
		ctx context.Context,
		req interface{},
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		interceptorCalled.Store(true)
		return handler(ctx, req)
	}

	server := NewServer(RequiredEngineParams{
		UnaryInterceptors: []grpc.UnaryServerInterceptor{customInterceptor},
	})
	healthServer := grpcHealth.NewServer()
	healthServer.SetServingStatus("", grpcHealthV1.HealthCheckResponse_SERVING)
	grpcHealthV1.RegisterHealthServer(server, healthServer)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to listen")
	t.Cleanup(func() {
		server.Stop()
		_ = lis.Close()
	})

	go func() { _ = server.Serve(lis) }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err, "failed to create grpc client")
	t.Cleanup(func() { _ = conn.Close() })

	client := grpcHealthV1.NewHealthClient(conn)
	_, err = client.Check(ctx, &grpcHealthV1.HealthCheckRequest{})
	require.NoError(t, err, "health check failed")

	require.True(t, interceptorCalled.Load(), "expected custom interceptor to be called")
}
