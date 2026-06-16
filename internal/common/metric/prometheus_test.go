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

package metric

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestNewPrometheus_RegistersCollectors(t *testing.T) {
	p := NewPrometheus()
	require.NotNil(t, p)
	require.NotNil(t, p.Registry())

	families, err := p.Registry().Gather()
	require.NoError(t, err)

	names := make(map[string]struct{}, len(families))
	for _, f := range families {
		names[f.GetName()] = struct{}{}
	}
	// Go runtime and process collectors are registered.
	require.Contains(t, names, "go_goroutines")
	require.Contains(t, names, "process_start_time_seconds")
}

func TestPrometheus_UnaryServerInterceptorRecordsMetrics(t *testing.T) {
	p := NewPrometheus()
	interceptor := p.UnaryServerInterceptor()
	require.NotNil(t, interceptor)

	info := &grpc.UnaryServerInfo{FullMethod: "/arc.signer.v1.SignerService/PublicKey"}
	handler := func(_ context.Context, _ any) (any, error) {
		return "ok", nil
	}

	resp, err := interceptor(context.Background(), nil, info, handler)
	require.NoError(t, err)
	require.Equal(t, "ok", resp)

	families, err := p.Registry().Gather()
	require.NoError(t, err)

	var handled bool
	for _, f := range families {
		if f.GetName() == "grpc_server_handled_total" {
			handled = true
		}
	}
	require.True(t, handled, "expected grpc_server_handled_total to be recorded by the interceptor")
}

func TestPrometheus_InitializeMetrics(t *testing.T) {
	p := NewPrometheus()
	server := grpc.NewServer()
	t.Cleanup(server.Stop)

	// InitializeMetrics must not panic for a server with no registered methods.
	require.NotPanics(t, func() {
		p.InitializeMetrics(server)
	})
}
