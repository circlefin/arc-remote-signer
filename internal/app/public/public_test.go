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
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/config"
	grpcServer "github.com/circlefin/arc-remote-signer/internal/common/grpc/server"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/stretchr/testify/require"
)

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
