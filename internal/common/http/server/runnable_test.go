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
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewRunnable_NameAndShutdown(t *testing.T) {
	server := &http.Server{}
	port := freeTCPPort(t)
	runnable, err := NewRunnable("test-service", server, WithListener("127.0.0.1", port))
	require.NoError(t, err)
	require.Equal(t, "test-service", runnable.Name())
	require.NoError(t, runnable.Shutdown(context.Background()))
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

func TestRunnableAddr_ReturnsConfiguredAddress(t *testing.T) {
	port := freeTCPPort(t)
	server := &http.Server{}
	runnable, err := NewRunnable("test-service", server, WithListener("127.0.0.1", port))
	require.NoError(t, err)

	runnableImpl, ok := runnable.(*RunnableImpl)
	require.True(t, ok, "expected runnable to be *RunnableImpl, got %T", runnable)

	addr := runnableImpl.Addr()
	require.NotNil(t, addr)
	require.Equal(t, fmt.Sprintf("127.0.0.1:%d", port), addr.String())
}

func TestRunnableShutdown_WithContext(t *testing.T) {
	port := freeTCPPort(t)
	server := &http.Server{}

	runnable, err := NewRunnable("test-service", server, WithListener("127.0.0.1", port))
	require.NoError(t, err)
	require.NoError(t, runnable.Run())

	require.NoError(t, runnable.Shutdown(context.Background()))
}

func TestNewRunnable_WithPortZero(t *testing.T) {
	server := &http.Server{}
	runnable, err := NewRunnable("test-service", server, WithListener("127.0.0.1", 0))
	require.NoError(t, err)
	require.NotNil(t, runnable)
}

func TestNewRunnable_WithoutListener(t *testing.T) {
	server := &http.Server{}
	_, err := NewRunnable("test-service", server)
	require.EqualError(t, err, "failed to initialize runnable http server: listener is not configured")
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
	server := &http.Server{}
	runnable := &RunnableImpl{
		name:     "test",
		server:   server,
		listener: nil,
	}

	require.NoError(t, runnable.Shutdown(context.Background()))
}

func TestRunnableShutdown_WithBeforeShutdownFns(t *testing.T) {
	port := freeTCPPort(t)
	server := &http.Server{}

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
	server := &http.Server{}

	runnable, err := NewRunnable("test-service", server, WithListener("127.0.0.1", port))
	require.NoError(t, err)
	require.NoError(t, runnable.Run())

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Stop the server - this should cause Serve() to return
	runnableImpl := runnable.(*RunnableImpl)
	err = runnableImpl.server.Shutdown(context.Background())
	require.NoError(t, err)

	// Give it a moment to process the stop
	time.Sleep(100 * time.Millisecond)
}

func TestRunnableShutdown_WithTimeout(t *testing.T) {
	port := freeTCPPort(t)
	server := &http.Server{}

	runnable, err := NewRunnable("test-service", server, WithListener("127.0.0.1", port))
	require.NoError(t, err)
	require.NoError(t, runnable.Run())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		time.Sleep(10 * time.Second)
		require.NoError(t, runnable.Shutdown(ctx))
	}()
	require.NoError(t, runnable.Shutdown(ctx))
}
