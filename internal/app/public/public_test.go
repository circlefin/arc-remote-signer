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
	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/status"
)

func newCreateServerParams(prometheus *metric.Prometheus) CreateServerParams {
	return CreateServerParams{
		ServiceName: "app.public",
		SignerSvc:   &pb.UnimplementedSignerServiceServer{},
		SignerV2Svc: &signerv2.UnimplementedSignerServiceServer{},
		Env:         config.Dev,
		Prometheus:  prometheus,
	}
}

func reflectionListServices(t *testing.T, cfg *grpcServer.Config) (*reflectionpb.ListServiceResponse, error) {
	t.Helper()

	runnable, err := New(cfg, newCreateServerParams(nil))
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
	require.Contains(t, services.Service, &reflectionpb.ServiceResponse{
		Name: signerv2.SignerService_ServiceDesc.ServiceName,
	})
}

func TestNew_ReturnsRunnableWithServiceName(t *testing.T) {
	cfg := &grpcServer.Config{
		Host: "127.0.0.1",
		Port: 0,
	}

	runnable, err := New(cfg, newCreateServerParams(nil))
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

	runnable, err := New(cfg, newCreateServerParams(nil))
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to load TLS options")
	require.Nil(t, runnable)
}

func TestReplicaIdentityInterceptor(t *testing.T) {
	t.Run("disabled without client authentication", func(t *testing.T) {
		require.NotNil(t, replicaIdentityInterceptor(nil))
		require.NotNil(t, replicaIdentityInterceptor(&grpcServer.TLSConfig{}))
	})

	t.Run("enabled for version 2 sign", func(t *testing.T) {
		identityInterceptor := replicaIdentityInterceptor(&grpcServer.TLSConfig{
			ClientAuth: grpcServer.ClientAuthConfig{Enabled: true},
		})
		require.NotNil(t, identityInterceptor)

		handlerCalled := false
		_, err := identityInterceptor(
			context.Background(),
			&signerv2.SignRequest{ReplicaName: "validator-01-a"},
			&grpc.UnaryServerInfo{FullMethod: signerv2.SignerService_Sign_FullMethodName},
			func(context.Context, interface{}) (interface{}, error) {
				handlerCalled = true
				return nil, nil
			},
		)

		require.NoError(t, err)
		require.True(t, handlerCalled)
	})
}

func TestNew_ReportsBothSignerServicesAsServing(t *testing.T) {
	cfg := &grpcServer.Config{
		Host: "127.0.0.1",
		Port: 0,
	}

	runnable, err := New(cfg, newCreateServerParams(nil))
	require.NoError(t, err)
	server := runnable.(*grpcServer.RunnableImpl)
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
			t.Errorf("close health client connection: %v", err)
		}
	})

	client := healthpb.NewHealthClient(conn)
	for _, serviceName := range []string{
		pb.SignerService_ServiceDesc.ServiceName,
		signerv2.SignerService_ServiceDesc.ServiceName,
	} {
		response, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{Service: serviceName})
		require.NoError(t, err)
		require.Equal(t, healthpb.HealthCheckResponse_SERVING, response.Status)
	}
}

func TestNew_PrometheusIncludesAllRegisteredServices(t *testing.T) {
	cfg := &grpcServer.Config{
		Host: "127.0.0.1",
		Port: 0,
	}
	prometheus := metric.NewPrometheus()

	runnable, err := New(cfg, newCreateServerParams(prometheus))
	require.NoError(t, err)
	require.NotNil(t, runnable)

	families, err := prometheus.Registry().Gather()
	require.NoError(t, err)
	registeredServices := make(map[string]bool)
	for _, family := range families {
		if family.GetName() != "grpc_server_started_total" {
			continue
		}
		for _, sample := range family.Metric {
			for _, label := range sample.Label {
				if label.GetName() == "grpc_service" {
					registeredServices[label.GetValue()] = true
				}
			}
		}
	}
	require.True(t, registeredServices[pb.SignerService_ServiceDesc.ServiceName])
	require.True(t, registeredServices[signerv2.SignerService_ServiceDesc.ServiceName])
	require.True(t, registeredServices[healthpb.Health_ServiceDesc.ServiceName])
}

func TestNew_ReturnsErrorWhenPortIsInvalid(t *testing.T) {
	cfg := &grpcServer.Config{
		Host: "127.0.0.1",
		Port: -1,
	}

	runnable, err := New(cfg, newCreateServerParams(nil))
	require.Error(t, err)
	require.Nil(t, runnable)
}
