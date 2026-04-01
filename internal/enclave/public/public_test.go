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

package public

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/circlefin/arc-remote-signer/internal/common/config"
	grpcServer "github.com/circlefin/arc-remote-signer/internal/common/grpc/server"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpcHealth "google.golang.org/grpc/health/grpc_health_v1"
)

func TestNew_ReturnsRunnableWithServiceName(t *testing.T) {
	cfg := &grpcServer.Config{
		Host: "127.0.0.1",
		Port: 0,
	}

	runnable, err := New(cfg, CreateServerParams{
		ServiceName:         "enclave.public",
		Env:                 config.Dev,
		EnclaveService:      &pb.UnimplementedEnclaveServiceServer{},
		NitroEnclaveEnabled: false,
	})
	require.NoError(t, err)
	require.NotNil(t, runnable)
	require.Equal(t, "enclave.public", runnable.Name())
}

func TestNew_ReturnsErrorWhenPortIsInvalid(t *testing.T) {
	cfg := &grpcServer.Config{
		Host: "127.0.0.1",
		Port: -1,
	}

	runnable, err := New(cfg, CreateServerParams{
		ServiceName:         "enclave.public",
		Env:                 config.Dev,
		EnclaveService:      &pb.UnimplementedEnclaveServiceServer{},
		NitroEnclaveEnabled: false,
	})
	require.Error(t, err)
	require.Nil(t, runnable)
}

func TestServer_StartsAndAcceptsConnections(t *testing.T) {
	// Get a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	_, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	require.NoError(t, listener.Close())

	// Convert port string to int
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	cfg := &grpcServer.Config{
		Host: "127.0.0.1",
		Port: port,
	}

	runnable, err := New(cfg, CreateServerParams{
		ServiceName:         "enclave.public",
		Env:                 config.Dev,
		EnclaveService:      &pb.UnimplementedEnclaveServiceServer{},
		NitroEnclaveEnabled: false,
	})
	require.NoError(t, err)
	require.NotNil(t, runnable)

	// Start server in background
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- runnable.Run()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create client and connect
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err, "failed to create client")
	defer func() { assert.NoError(t, conn.Close()) }()

	// Verify health check works (this implicitly tests connectivity)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	healthClient := grpcHealth.NewHealthClient(conn)
	healthResp, err := healthClient.Check(ctx, &grpcHealth.HealthCheckRequest{
		Service: pb.EnclaveService_ServiceDesc.ServiceName,
	})
	require.NoError(t, err, "health check failed")
	require.Equal(t, grpcHealth.HealthCheckResponse_SERVING, healthResp.Status)

	// Shutdown server gracefully
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	err = runnable.Shutdown(shutdownCtx)
	require.NoError(t, err, "failed to shutdown server gracefully")

	// Verify server stopped
	select {
	case err := <-serverErr:
		require.NoError(t, err, "server returned error")
	case <-time.After(2 * time.Second):
		require.Fail(t, "server did not stop after shutdown")
	}
}
