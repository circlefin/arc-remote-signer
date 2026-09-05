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

package enclave

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	grpcClient "github.com/circlefin/arc-remote-signer/internal/common/grpc/client"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type internalInitializeServer struct {
	pb.UnimplementedEnclaveServiceServer
	calls atomic.Int32
}

func (s *internalInitializeServer) Initialize(
	context.Context,
	*pb.InitializeRequest,
) (*pb.InitializeResponse, error) {
	s.calls.Add(1)
	return nil, status.Error(codes.Internal, "cryptographic failure")
}

func TestNew_Success(t *testing.T) {
	cfg := NewProviderConfig()
	cfg.Client.BaseURL = ":10350"

	client, conn, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
	require.NotNil(t, conn)
	require.NoError(t, conn.Close())
}

func TestNew_NilProviderConfig(t *testing.T) {
	client, conn, err := New(nil)

	require.Nil(t, client)
	require.Nil(t, conn)
	require.Error(t, err)
	require.EqualError(t, err, "provider config is nil")
}

func TestNew_NilClientConfig(t *testing.T) {
	client, conn, err := New(&ProviderConfig{})

	require.Nil(t, client)
	require.Nil(t, conn)
	require.Error(t, err)
	require.EqualError(t, err, "provider client config is nil")
}

func TestNew_NitroEnabledWithInvalidCID(t *testing.T) {
	cfg := NewProviderConfig()
	cfg.NitroEnclave.Enabled = true
	cfg.NitroEnclave.CID = 0

	client, conn, err := New(cfg)

	require.Nil(t, client)
	require.Nil(t, conn)
	require.Error(t, err)
	require.EqualError(t, err, "nitro enclave mode requires a valid CID and port")
}

func TestNew_NitroEnabledWithInvalidPort(t *testing.T) {
	cfg := NewProviderConfig()
	cfg.NitroEnclave.Enabled = true
	cfg.NitroEnclave.CID = 16
	cfg.NitroEnclave.Port = 0

	client, conn, err := New(cfg)

	require.Nil(t, client)
	require.Nil(t, conn)
	require.Error(t, err)
	require.EqualError(t, err, "nitro enclave mode requires a valid CID and port")
}

func TestNew_InvalidTarget(t *testing.T) {
	cfg := &ProviderConfig{
		NitroEnclave: &NitroEnclave{},
		Client: &grpcClient.Config{
			BaseURL: "http://localhost:10350",
		},
	}

	client, conn, err := New(cfg)
	require.Nil(t, client)
	require.Nil(t, conn)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to create enclave client connection")
}

func TestNew_InitializeInternalResponseHasOneTransportAttempt(t *testing.T) {
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	enclaveServer := &internalInitializeServer{}
	pb.RegisterEnclaveServiceServer(server, enclaveServer)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	cfg := NewProviderConfig()
	cfg.Client.BaseURL = listener.Addr().String()
	cfg.Client.Retry.MaxAttempts = 3
	cfg.Client.Methods["initialize"] = grpcClient.MethodConfig{
		TimeoutMS:   1000,
		MaxAttempts: 3,
	}
	cfg.Client.Methods["Initialize"] = grpcClient.MethodConfig{
		TimeoutMS:   1000,
		MaxAttempts: 3,
	}
	client, conn, err := New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	resp, err := client.Initialize(context.Background(), &pb.InitializeRequest{})

	require.Nil(t, resp)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Equal(t, int32(1), enclaveServer.calls.Load())
}

func TestPinInitializeTransportAttempts(t *testing.T) {
	t.Run("missing Initialize entry uses startup timeout", func(t *testing.T) {
		cfg := grpcClient.Config{
			RequestTimeoutMS: 500,
			Methods: map[string]grpcClient.MethodConfig{
				"signmessage": {TimeoutMS: 500, MaxAttempts: 3},
			},
		}

		got := pinInitializeTransportAttempts(cfg)

		require.Equal(t, grpcClient.MethodConfig{
			TimeoutMS:   defaultStartupTimeoutMS,
			MaxAttempts: 1,
		}, got.Methods["initialize"])
	})

	t.Run("custom Initialize aliases retain timeouts", func(t *testing.T) {
		cfg := grpcClient.Config{
			Methods: map[string]grpcClient.MethodConfig{
				"initialize": {TimeoutMS: 41000, MaxAttempts: 4},
				"Initialize": {TimeoutMS: 42000, MaxAttempts: 5},
				"/arc.enclave.v1.EnclaveService/Initialize": {TimeoutMS: 43000, MaxAttempts: 6},
			},
		}

		got := pinInitializeTransportAttempts(cfg)

		require.Equal(t, grpcClient.MethodConfig{TimeoutMS: 41000, MaxAttempts: 1}, got.Methods["initialize"])
		require.Equal(t, grpcClient.MethodConfig{TimeoutMS: 42000, MaxAttempts: 1}, got.Methods["Initialize"])
		require.Equal(t, grpcClient.MethodConfig{
			TimeoutMS:   43000,
			MaxAttempts: 1,
		}, got.Methods["/arc.enclave.v1.EnclaveService/Initialize"])
	})
}

func TestNewNitro_IgnoresRuntimeToggle(t *testing.T) {
	cfg := NewProviderConfig()
	cfg.NitroEnclave.Enabled = false

	client, conn, err := NewNitro(cfg)

	require.NoError(t, err)
	require.NotNil(t, client)
	require.NotNil(t, conn)
	require.NoError(t, conn.Close())
}

func TestNewNitro_RequiresCIDAndPort(t *testing.T) {
	nilNitroConfig := NewProviderConfig()
	nilNitroConfig.NitroEnclave = nil
	zeroCIDConfig := NewProviderConfig()
	zeroCIDConfig.NitroEnclave.CID = 0
	zeroPortConfig := NewProviderConfig()
	zeroPortConfig.NitroEnclave.Port = 0

	tests := []struct {
		name string
		cfg  *ProviderConfig
	}{
		{name: "provider configuration is nil", cfg: nil},
		{name: "Nitro configuration is nil", cfg: nilNitroConfig},
		{name: "CID is zero", cfg: zeroCIDConfig},
		{name: "port is zero", cfg: zeroPortConfig},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, conn, err := NewNitro(tt.cfg)

			require.Nil(t, client)
			require.Nil(t, conn)
			require.ErrorContains(t, err, "requires a valid CID and port")
		})
	}
}
