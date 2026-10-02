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
	"io"
	"testing"
	"time"

	"github.com/circlefin/arc-remote-signer/internal/common/config"
	grpcServer "github.com/circlefin/arc-remote-signer/internal/common/grpc/server"
	"github.com/circlefin/arc-remote-signer/internal/common/metric"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/status"
)

func reflectionListServices(t *testing.T, cfg *grpcServer.Config) (*reflectionpb.ListServiceResponse, error) {
	t.Helper()

	runnable, err := New(cfg, CreateServerParams{
		ServiceName: "app.public",
		SignerSvc:   &pb.UnimplementedSignerServiceServer{},
		Env:         config.Dev,
	})
	require.NoError(t, err)

	server, ok := runnable.(*grpcServer.RunnableImpl)
	require.True(t, ok)
	require.NoError(t, server.Run())
	t.Cleanup(func() {
		if err := server.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown gRPC server: %v", err)
		}
	})

	conn, err := grpc.NewClient(
		server.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close reflection client connection: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := reflectionpb.NewServerReflectionClient(conn).ServerReflectionInfo(ctx)
	require.NoError(t, err)
	err = stream.Send(&reflectionpb.ServerReflectionRequest{
		MessageRequest: &reflectionpb.ServerReflectionRequest_ListServices{
			ListServices: "",
		},
	})
	if err != nil && err != io.EOF {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	return resp.GetListServicesResponse(), nil
}

func TestNew_DisablesReflectionByDefault(t *testing.T) {
	cfg := &grpcServer.Config{
		Host: "127.0.0.1",
		Port: 0,
	}

	services, err := reflectionListServices(t, cfg)
	require.Error(t, err)
	require.Equal(t, codes.Unimplemented, status.Code(err))
	require.Nil(t, services)
}

func TestNew_EnablesReflectionWhenConfigured(t *testing.T) {
	cfg := &grpcServer.Config{
		Host: "127.0.0.1",
		Port: 0,
		Reflection: grpcServer.ReflectionConfig{
			Enabled: true,
		},
	}

	services, err := reflectionListServices(t, cfg)
	require.NoError(t, err)
	require.NotNil(t, services)
	require.Contains(t, services.Service, &reflectionpb.ServiceResponse{
		Name: pb.SignerService_ServiceDesc.ServiceName,
	})
}

func TestNew_ReturnsRunnableWithServiceName(t *testing.T) {
	cfg := &grpcServer.Config{
		Host: "127.0.0.1",
		Port: 0,
	}

	runnable, err := New(cfg, CreateServerParams{
		ServiceName: "app.public",
		SignerSvc:   &pb.UnimplementedSignerServiceServer{},
		Env:         config.Dev,
	})
	require.NoError(t, err)
	require.NotNil(t, runnable)
	require.Equal(t, "app.public", runnable.Name())
}

func TestNew_ReturnsErrorWhenTLSConfigInvalid(t *testing.T) {
	cfg := &grpcServer.Config{
		Host: "127.0.0.1",
		Port: 0,
		TLS:  &grpcServer.TLSConfig{Enabled: true},
	}

	runnable, err := New(cfg, CreateServerParams{
		ServiceName: "app.public",
		SignerSvc:   &pb.UnimplementedSignerServiceServer{},
		Env:         config.Dev,
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to load TLS options")
	require.Nil(t, runnable)
}

func TestNew_WithPrometheusProvider(t *testing.T) {
	cfg := &grpcServer.Config{
		Host: "127.0.0.1",
		Port: 0,
	}

	runnable, err := New(cfg, CreateServerParams{
		ServiceName: "app.public",
		SignerSvc:   &pb.UnimplementedSignerServiceServer{},
		Env:         config.Dev,
		Prometheus:  metric.NewPrometheus(),
	})
	require.NoError(t, err)
	require.NotNil(t, runnable)
	require.Equal(t, "app.public", runnable.Name())
}

func TestNew_ReturnsErrorWhenPortIsInvalid(t *testing.T) {
	cfg := &grpcServer.Config{
		Host: "127.0.0.1",
		Port: -1,
	}

	runnable, err := New(cfg, CreateServerParams{
		ServiceName: "app.public",
		SignerSvc:   &pb.UnimplementedSignerServiceServer{},
		Env:         config.Dev,
	})
	require.Error(t, err)
	require.Nil(t, runnable)
}
