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

package client

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcHealthV1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

type testHealthServer struct {
	grpcHealthV1.UnimplementedHealthServer
	mu                   sync.Mutex
	calls                int
	failUntil            int
	blockUntilCtxTimeout bool
}

func (s *testHealthServer) Check(ctx context.Context, _ *grpcHealthV1.HealthCheckRequest) (*grpcHealthV1.HealthCheckResponse, error) {
	if s.blockUntilCtxTimeout {
		<-ctx.Done()
		return nil, status.Error(codes.DeadlineExceeded, ctx.Err().Error())
	}
	s.mu.Lock()
	s.calls++
	current := s.calls
	s.mu.Unlock()
	if current <= s.failUntil {
		return nil, status.Error(codes.Unavailable, "temporary unavailable")
	}
	return &grpcHealthV1.HealthCheckResponse{Status: grpcHealthV1.HealthCheckResponse_SERVING}, nil
}

func (s *testHealthServer) Watch(*grpcHealthV1.HealthCheckRequest, grpcHealthV1.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "watch not implemented")
}

func (s *testHealthServer) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func startHealthServer(t *testing.T, svc grpcHealthV1.HealthServer) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err, "listen failed")

	s := grpc.NewServer()
	grpcHealthV1.RegisterHealthServer(s, svc)
	go func() { _ = s.Serve(lis) }()

	return lis.Addr().String(), func() {
		s.Stop()
		_ = lis.Close()
	}
}

func TestNewInsecureClientConnRetriesUnavailable(t *testing.T) {
	svc := &testHealthServer{failUntil: 2}
	addr, stop := startHealthServer(t, svc)
	defer stop()

	conn, err := NewInsecureClientConn(addr, Config{
		RequestTimeoutMS: 1000,
		Retry: &RetryConfig{
			MaxAttempts: 3,
		},
	})
	require.NoError(t, err, "failed to create client conn")
	t.Cleanup(func() { _ = conn.Close() })

	client := grpcHealthV1.NewHealthClient(conn)
	_, err = client.Check(context.Background(), &grpcHealthV1.HealthCheckRequest{})
	require.NoError(t, err, "expected success after retries")
	require.Equal(t, 3, svc.Calls(), "expected 3 attempts")
}

func TestNewInsecureClientConnAcceptsLocalhostHostPort(t *testing.T) {
	svc := &testHealthServer{}
	addr, stop := startHealthServer(t, svc)
	defer stop()

	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err, "failed to split host/port")

	conn, err := NewInsecureClientConn(net.JoinHostPort("localhost", port), Config{
		RequestTimeoutMS: 1000,
		Retry: &RetryConfig{
			MaxAttempts: 1,
		},
	})
	require.NoError(t, err, "failed to create client conn with localhost target")
	t.Cleanup(func() { _ = conn.Close() })

	client := grpcHealthV1.NewHealthClient(conn)
	_, err = client.Check(context.Background(), &grpcHealthV1.HealthCheckRequest{})
	require.NoError(t, err, "expected localhost target to work")
}

func TestNewInsecureClientConnRejectsNonHostPortTarget(t *testing.T) {
	_, err := NewInsecureClientConn("http://localhost:10350", Config{
		RequestTimeoutMS: 1000,
		Retry: &RetryConfig{
			MaxAttempts: 1,
		},
	})
	require.Error(t, err, "expected invalid target error")
}

func TestNewInsecureClientConnTimeout(t *testing.T) {
	svc := &testHealthServer{blockUntilCtxTimeout: true}
	addr, stop := startHealthServer(t, svc)
	defer stop()

	conn, err := NewInsecureClientConn(addr, Config{
		RequestTimeoutMS: 10,
		Retry: &RetryConfig{
			MaxAttempts: 0,
		},
	})
	require.NoError(t, err, "failed to create client conn")
	t.Cleanup(func() { _ = conn.Close() })

	client := grpcHealthV1.NewHealthClient(conn)
	_, err = client.Check(context.Background(), &grpcHealthV1.HealthCheckRequest{})
	require.Equal(t, codes.DeadlineExceeded, status.Code(err), "expected deadline exceeded")
}

func TestNewInsecureClientConnCustomRetryCodes(t *testing.T) {
	svc := &testHealthServer{failUntil: 1}
	addr, stop := startHealthServer(t, svc)
	defer stop()

	conn, err := NewInsecureClientConn(addr, Config{
		RequestTimeoutMS: 1000,
		Retry: &RetryConfig{
			MaxAttempts: 3,
			RetryCodes:  []codes.Code{codes.Aborted},
		},
	})
	require.NoError(t, err, "failed to create client conn")
	t.Cleanup(func() { _ = conn.Close() })

	client := grpcHealthV1.NewHealthClient(conn)
	_, err = client.Check(context.Background(), &grpcHealthV1.HealthCheckRequest{})
	require.Equal(t, codes.Unavailable, status.Code(err), "expected unavailable")
	require.Equal(t, 1, svc.Calls(), "expected 1 attempt")
}
