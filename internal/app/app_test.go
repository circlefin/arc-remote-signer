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

package app

import (
	"context"
	"testing"
	"time"

	enclaveProvider "github.com/circlefin/arc-remote-signer/internal/app/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

func TestNewInitializeKeyFunc_AppliesTotalTimeout(t *testing.T) {
	ctrl := gomock.NewController(t)
	enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	enclavePvd.EXPECT().
		Initialize(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, _ *pb.InitializeRequest, _ ...any) (*pb.InitializeResponse, error) {
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			require.WithinDuration(t, time.Now().Add(time.Hour), deadline, time.Second)
			return &pb.InitializeResponse{}, nil
		})

	initializeKey := newInitializeKeyFunc(
		&enclaveProvider.ProviderConfig{StartupTimeoutMS: int(time.Hour.Milliseconds())},
		enclavePvd,
		newTestAwsCfg(t),
		testArns,
		false,
		logging.Get("test"),
	)
	resp, err := initializeKey(context.Background(), nil, pb.Algorithm_ALGORITHM_ED25519)

	require.NoError(t, err)
	require.NotNil(t, resp)
}
