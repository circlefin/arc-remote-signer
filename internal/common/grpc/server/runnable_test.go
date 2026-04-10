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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpcHealth "google.golang.org/grpc/health"
	grpcHealthV1 "google.golang.org/grpc/health/grpc_health_v1"
)

func TestNewRunnable_NameAndShutdown(t *testing.T) {
	server := grpc.NewServer()
	port := freeTCPPort(t)
	runnable, err := NewRunnable("test-service", server, WithListener(ListenerTransportTCP, "127.0.0.1", port))
	require.NoError(t, err)
	require.Equal(t, "test-service", runnable.Name())
	require.NoError(t, runnable.Shutdown(context.Background()))
}

func TestRunnableRun_Serves(t *testing.T) {
	port := freeTCPPort(t)
	server := grpc.NewServer()
	healthServer := grpcHealth.NewServer()
	healthServer.SetServingStatus("", grpcHealthV1.HealthCheckResponse_SERVING)
	grpcHealthV1.RegisterHealthServer(server, healthServer)

	runnable, err := NewRunnable("test-service", server, WithListener(ListenerTransportTCP, "127.0.0.1", port))
	require.NoError(t, err)
	require.NoError(t, runnable.Run())

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.NoError(t, waitForHealth(addr, 2*time.Second), "server did not become ready")
}

func freeTCPPort(t *testing.T) uint32 {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to reserve port")
	defer func() { _ = lis.Close() }()

	tcpAddr, ok := lis.Addr().(*net.TCPAddr)
	require.True(t, ok, "failed to cast addr to tcp addr: %T", lis.Addr())
	return uint32(tcpAddr.Port)
}

func waitForHealth(addr string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err == nil {
			client := grpcHealthV1.NewHealthClient(conn)
			checkCtx, checkCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			_, callErr := client.Check(checkCtx, &grpcHealthV1.HealthCheckRequest{})
			checkCancel()
			_ = conn.Close()
			if callErr == nil {
				return nil
			}
		}

		time.Sleep(20 * time.Millisecond)
	}
}

func TestRunnableAddr_ReturnsConfiguredAddress(t *testing.T) {
	port := freeTCPPort(t)
	server := grpc.NewServer()
	runnable, err := NewRunnable("test-service", server, WithListener(ListenerTransportTCP, "127.0.0.1", port))
	require.NoError(t, err)

	runnableImpl, ok := runnable.(*RunnableImpl)
	require.True(t, ok, "expected runnable to be *RunnableImpl, got %T", runnable)

	addr := runnableImpl.Addr()
	require.NotNil(t, addr)
	require.Equal(t, fmt.Sprintf("127.0.0.1:%d", port), addr.String())
}

func TestRunnableShutdown_WithContext(t *testing.T) {
	port := freeTCPPort(t)
	server := grpc.NewServer()
	healthServer := grpcHealth.NewServer()
	healthServer.SetServingStatus("", grpcHealthV1.HealthCheckResponse_SERVING)
	grpcHealthV1.RegisterHealthServer(server, healthServer)

	runnable, err := NewRunnable("test-service", server, WithListener(ListenerTransportTCP, "127.0.0.1", port))
	require.NoError(t, err)
	require.NoError(t, runnable.Run())

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.NoError(t, waitForHealth(addr, 2*time.Second), "server did not become ready")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, runnable.Shutdown(ctx))
}

func TestNewRunnable_WithPortZero(t *testing.T) {
	server := grpc.NewServer()
	runnable, err := NewRunnable("test-service", server, WithListener(ListenerTransportTCP, "127.0.0.1", 0))
	require.NoError(t, err)
	require.NotNil(t, runnable)
}

func TestNewRunnable_WithoutListener(t *testing.T) {
	server := grpc.NewServer()
	_, err := NewRunnable("test-service", server)
	require.EqualError(t, err, "failed to initialize runnable grpc server: listener is not configured")
}

func TestRunnableAddr_NilListener(t *testing.T) {
	runnable := &RunnableImpl{
		name:     "test",
		listener: nil,
	}

	addr := runnable.Addr()
	require.Nil(t, addr)
}

func TestRunnableShutdown_NilListener(t *testing.T) {
	server := grpc.NewServer()
	runnable := &RunnableImpl{
		name:     "test",
		server:   server,
		listener: nil,
	}

	require.NoError(t, runnable.Shutdown(context.Background()))
}

func TestRunnableShutdown_WithBeforeShutdownFns(t *testing.T) {
	port := freeTCPPort(t)
	server := grpc.NewServer()

	called := false
	beforeShutdown := func() {
		called = true
	}

	runnable := &RunnableImpl{
		name:              "test",
		server:            server,
		beforeShutdownFns: []func(){beforeShutdown},
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err, "failed to create listener")
	runnable.listener = lis

	require.NoError(t, runnable.Shutdown(context.Background()))
	require.True(t, called)
}

func TestRunnableRun_ErrorInServe(t *testing.T) {
	port := freeTCPPort(t)
	server := grpc.NewServer()

	runnable, err := NewRunnable("test-service", server, WithListener(ListenerTransportTCP, "127.0.0.1", port))
	require.NoError(t, err)
	require.NoError(t, runnable.Run())

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Stop the server - this should cause Serve() to return
	runnableImpl := runnable.(*RunnableImpl)
	runnableImpl.server.Stop()

	// Give it a moment to process the stop
	time.Sleep(100 * time.Millisecond)
}
