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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpcHealthV1 "google.golang.org/grpc/health/grpc_health_v1"
)

func TestWithListener_TCPSuccess(t *testing.T) {
	r := &RunnableImpl{server: grpc.NewServer()}
	port := freeTCPPort(t)

	err := WithListener(ListenerTransportTCP, "127.0.0.1", port)(r)
	require.NoError(t, err)
	require.NotNil(t, r.listener)
	_ = r.listener.Close()
}

func TestWithListener_TCPPortInUse(t *testing.T) {
	r := &RunnableImpl{server: grpc.NewServer()}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to create occupied listener")
	defer func() { _ = lis.Close() }()

	tcpAddr, ok := lis.Addr().(*net.TCPAddr)
	require.True(t, ok, "failed to cast addr to tcp addr: %T", lis.Addr())

	err = WithListener(ListenerTransportTCP, "127.0.0.1", uint32(tcpAddr.Port))(r)
	require.Error(t, err)
}

func TestWithListener_VSOCKBranch(t *testing.T) {
	r := &RunnableImpl{server: grpc.NewServer()}
	err := WithListener(ListenerTransportVSOCK, "", 5005)(r)

	// This assertion keeps the test portable:
	// environments without VSOCK support should return an error,
	// while supported environments may succeed and provide a listener.
	if err == nil {
		require.NotNil(t, r.listener, "expected either vsock setup error or configured listener")
		_ = r.listener.Close()
	}
}

func TestWithListener_UnsupportedTransport(t *testing.T) {
	r := &RunnableImpl{server: grpc.NewServer()}
	err := WithListener(ListenerTransport("unknown"), "127.0.0.1", 0)(r)
	require.Error(t, err)
}

func TestWithHealthServer_LifecycleStatus(t *testing.T) {
	server := grpc.NewServer()
	r := &RunnableImpl{server: server}

	require.NoError(t, WithHealthServer("test.service")(r))
	require.Len(t, r.beforeShutdownFns, 1)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to create listener")
	defer func() {
		server.Stop()
		_ = lis.Close()
	}()

	go func() { _ = server.Serve(lis) }()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err, "failed to create grpc client")
	defer func() { _ = conn.Close() }()

	client := grpcHealthV1.NewHealthClient(conn)

	waitForStatus(t, client, "", grpcHealthV1.HealthCheckResponse_SERVING)
	waitForStatus(t, client, "test.service", grpcHealthV1.HealthCheckResponse_SERVING)

	r.beforeShutdownFns[0]()

	waitForStatus(t, client, "", grpcHealthV1.HealthCheckResponse_NOT_SERVING)
	waitForStatus(t, client, "test.service", grpcHealthV1.HealthCheckResponse_NOT_SERVING)
}

func waitForStatus(t *testing.T, client grpcHealthV1.HealthClient, service string, want grpcHealthV1.HealthCheckResponse_ServingStatus) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		resp, err := client.Check(ctx, &grpcHealthV1.HealthCheckRequest{Service: service})
		cancel()
		if err == nil && resp.GetStatus() == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.Failf(t, "health status timeout", "health status for service %q did not become %s", service, want.String())
}
