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
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	enclaveProvider "github.com/circlefin/arc-remote-signer/internal/app/provider/enclave"
	signerv1 "github.com/circlefin/arc-remote-signer/internal/app/service/signer/v1"
	signerv2service "github.com/circlefin/arc-remote-signer/internal/app/service/signer/v2"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/internal/common/watermark"
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
	resp, err := initializeKey(
		context.Background(),
		nil,
		pb.Algorithm_ALGORITHM_ED25519,
	)

	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestNewSignerV2Service_ForwardsExactAWSConfigAndValidatorKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	repository := watermark.NewMockOwnedAdvancer(ctrl)
	awsConfig := aws.Config{Region: "us-west-2"}
	validatorKey := []byte("validator-public-key")
	factoryCalled := false

	service, err := newSignerV2Service(
		&signerv1.Service{},
		awsConfig,
		validatorKey,
		func(gotConfig aws.Config, gotKey []byte) (watermark.OwnedAdvancer, error) {
			factoryCalled = true
			require.Equal(t, awsConfig, gotConfig)
			require.Equal(t, validatorKey, gotKey)
			return repository, nil
		},
	)

	require.NoError(t, err)
	require.IsType(t, &signerv2service.Service{}, service)
	require.True(t, factoryCalled)
}

func TestNewSignerV2Service_ReturnsRepositoryFactoryError(t *testing.T) {
	factoryError := errors.New("DynamoDB configuration rejected")

	service, err := newSignerV2Service(
		&signerv1.Service{},
		aws.Config{Region: "eu-west-1"},
		[]byte("validator-public-key"),
		func(aws.Config, []byte) (watermark.OwnedAdvancer, error) {
			return nil, factoryError
		},
	)

	require.Nil(t, service)
	require.ErrorIs(t, err, factoryError)
	require.ErrorContains(t, err, "create watermark repository")
}
