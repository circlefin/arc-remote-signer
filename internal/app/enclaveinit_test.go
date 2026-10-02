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
	"github.com/aws/aws-sdk-go-v2/credentials"
	enclaveProvider "github.com/circlefin/arc-remote-signer/internal/app/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// withFastBackoff temporarily zeroes the Initialize retry backoff so the
// retry table can exercise three attempts in milliseconds rather than
// seconds. Mutating package-level state is acceptable here because the
// app-level tests do not run in parallel.
func withFastBackoff(t *testing.T) {
	t.Helper()
	saved := initRetryBackoff
	initRetryBackoff = 0
	t.Cleanup(func() { initRetryBackoff = saved })
}

func newTestAwsCfg(t *testing.T) aws.Config {
	t.Helper()
	return aws.Config{
		Region: "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider(
			"AKIA-test",
			"secret",
			"session",
		),
	}
}

var testArns = []string{"arn:aws:kms:us-east-1:000000000000:key/abc"}
var testKeySource = enclaveKeySource{generateNew: pb.Algorithm_ALGORITHM_ED25519}

func TestInitializeEnclave_Success(t *testing.T) {
	withFastBackoff(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	mockClient.EXPECT().
		Initialize(gomock.Any(), gomock.Any()).
		Return(&pb.InitializeResponse{}, nil).
		Times(1)

	_, err := initializeEnclave(context.Background(), mockClient, newTestAwsCfg(t), testArns, false, testKeySource, logging.Get("test"))
	require.NoError(t, err)
}

func TestInitializeEnclave_RequestShape(t *testing.T) {
	withFastBackoff(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var captured *pb.InitializeRequest
	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	mockClient.EXPECT().
		Initialize(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, req *pb.InitializeRequest, _ ...any) (*pb.InitializeResponse, error) {
			captured = req
			return &pb.InitializeResponse{}, nil
		}).
		Times(1)

	_, err := initializeEnclave(context.Background(), mockClient, newTestAwsCfg(t), testArns, true, testKeySource, logging.Get("test"))
	require.NoError(t, err)
	require.NotNil(t, captured)
	require.NotNil(t, captured.Credentials)
	require.Equal(t, "AKIA-test", captured.Credentials.AccessKeyId)
	require.Equal(t, "secret", captured.Credentials.SecretAccessKey)
	require.Equal(t, "session", captured.Credentials.SessionToken)
	require.Equal(t, "us-east-1", captured.Credentials.Region)
	require.Equal(t, testArns, captured.KmsKeyArns)
	require.True(t, captured.KmsLocalstackEnabled)
	require.Equal(t, pb.Algorithm_ALGORITHM_ED25519, captured.GetGenerateNew())
}

func TestInitializeEnclave_ExistingKeyRequestShape(t *testing.T) {
	withFastBackoff(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	existingKey := &pb.SecretEnvelope{
		Algorithm:           pb.Algorithm_ALGORITHM_ED25519,
		KmsEncryptedDataKey: []byte("kms-key"),
		EncryptedPrivateKey: []byte("private-key"),
		Nonce:               []byte("nonce"),
	}
	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	mockClient.EXPECT().
		Initialize(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, req *pb.InitializeRequest, _ ...any) (*pb.InitializeResponse, error) {
			require.Equal(t, existingKey, req.GetExistingKey())
			require.Equal(t, pb.Algorithm_ALGORITHM_UNSPECIFIED, req.GetGenerateNew())
			return &pb.InitializeResponse{PublicKey: []byte("public-key")}, nil
		})

	resp, err := initializeEnclave(
		context.Background(),
		mockClient,
		newTestAwsCfg(t),
		testArns,
		false,
		enclaveKeySource{existingKey: existingKey},
		logging.Get("test"),
	)

	require.NoError(t, err)
	require.Equal(t, []byte("public-key"), resp.PublicKey)
}

func TestInitializeEnclave_RetriesUnavailableThenSucceeds(t *testing.T) {
	withFastBackoff(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	unavailErr := status.Error(codes.Unavailable, "enclave not ready")
	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	gomock.InOrder(
		mockClient.EXPECT().Initialize(gomock.Any(), gomock.Any()).Return(nil, unavailErr),
		mockClient.EXPECT().Initialize(gomock.Any(), gomock.Any()).Return(nil, unavailErr),
		mockClient.EXPECT().Initialize(gomock.Any(), gomock.Any()).Return(&pb.InitializeResponse{}, nil),
	)

	_, err := initializeEnclave(context.Background(), mockClient, newTestAwsCfg(t), testArns, false, testKeySource, logging.Get("test"))
	require.NoError(t, err)
}

func TestInitializeEnclave_RetrievesCredentialsForEachAttempt(t *testing.T) {
	withFastBackoff(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	credentialsProvider := &rotatingCredentialProvider{
		values: []aws.Credentials{
			{AccessKeyID: "AKIA-first", SecretAccessKey: "secret-1", SessionToken: "session-1"},
			{AccessKeyID: "AKIA-second", SecretAccessKey: "secret-2", SessionToken: "session-2"},
		},
	}
	var accessKeyIDs []string
	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	gomock.InOrder(
		mockClient.EXPECT().
			Initialize(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, req *pb.InitializeRequest, _ ...any) (*pb.InitializeResponse, error) {
				accessKeyIDs = append(accessKeyIDs, req.GetCredentials().GetAccessKeyId())
				return nil, status.Error(codes.Unavailable, "try again")
			}),
		mockClient.EXPECT().
			Initialize(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, req *pb.InitializeRequest, _ ...any) (*pb.InitializeResponse, error) {
				accessKeyIDs = append(accessKeyIDs, req.GetCredentials().GetAccessKeyId())
				return &pb.InitializeResponse{}, nil
			}),
	)

	_, err := initializeEnclave(
		context.Background(),
		mockClient,
		aws.Config{Region: "us-east-1", Credentials: credentialsProvider},
		testArns,
		false,
		testKeySource,
		logging.Get("test"),
	)

	require.NoError(t, err)
	require.Equal(t, []string{"AKIA-first", "AKIA-second"}, accessKeyIDs)
	require.Equal(t, 2, credentialsProvider.retrieveCalls)
}

func TestInitializeEnclave_InvalidatesCachedCredentialsAfterUnauthenticated(t *testing.T) {
	withFastBackoff(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	credentialsProvider := &rotatingCredentialProvider{
		values: []aws.Credentials{
			{AccessKeyID: "AKIA-expired", SecretAccessKey: "secret-1", SessionToken: "session-1"},
			{AccessKeyID: "AKIA-refreshed", SecretAccessKey: "secret-2", SessionToken: "session-2"},
		},
	}
	cachedCredentials := aws.NewCredentialsCache(credentialsProvider)
	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	gomock.InOrder(
		mockClient.EXPECT().
			Initialize(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, req *pb.InitializeRequest, _ ...any) (*pb.InitializeResponse, error) {
				require.Equal(t, "AKIA-expired", req.GetCredentials().GetAccessKeyId())
				return nil, status.Error(codes.Unauthenticated, "expired credentials")
			}),
		mockClient.EXPECT().
			Initialize(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, req *pb.InitializeRequest, _ ...any) (*pb.InitializeResponse, error) {
				require.Equal(t, "AKIA-refreshed", req.GetCredentials().GetAccessKeyId())
				return &pb.InitializeResponse{}, nil
			}),
	)

	_, err := initializeEnclave(
		context.Background(),
		mockClient,
		aws.Config{Region: "us-east-1", Credentials: cachedCredentials},
		testArns,
		false,
		testKeySource,
		logging.Get("test"),
	)

	require.NoError(t, err)
	require.Equal(t, 2, credentialsProvider.retrieveCalls)
}

func TestInitializeEnclave_ExhaustsRetriesOnUnavailable(t *testing.T) {
	withFastBackoff(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	unavailErr := status.Error(codes.Unavailable, "enclave still not ready")
	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	mockClient.EXPECT().
		Initialize(gomock.Any(), gomock.Any()).
		Return(nil, unavailErr).
		Times(initRetryAttempts)

	_, err := initializeEnclave(context.Background(), mockClient, newTestAwsCfg(t), testArns, false, testKeySource, logging.Get("test"))
	require.Error(t, err)
	require.ErrorIs(t, err, unavailErr)
	require.Contains(t, err.Error(), "exhausted")
}

func TestInitializeEnclave_RetriesDeadlineExceededThenSucceeds(t *testing.T) {
	withFastBackoff(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	deadlineErr := status.Error(codes.DeadlineExceeded, "deadline exceeded during enclave cold start")
	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	gomock.InOrder(
		mockClient.EXPECT().Initialize(gomock.Any(), gomock.Any()).Return(nil, deadlineErr),
		mockClient.EXPECT().Initialize(gomock.Any(), gomock.Any()).Return(&pb.InitializeResponse{}, nil),
	)

	_, err := initializeEnclave(context.Background(), mockClient, newTestAwsCfg(t), testArns, false, testKeySource, logging.Get("test"))
	require.NoError(t, err)
}

func TestInitializeEnclave_EmptyKmsKeyArnsRejected(t *testing.T) {
	withFastBackoff(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Mock not expected to be called — guard fires before any RPC.
	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)

	_, err := initializeEnclave(context.Background(), mockClient, newTestAwsCfg(t), nil, false, testKeySource, logging.Get("test"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "kmsKeyArns must not be empty")
}

func TestInitializeEnclave_NonRetryablePermissionDenied(t *testing.T) {
	withFastBackoff(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	deniedErr := status.Error(codes.PermissionDenied, "kms:GenerateDataKey not allowed")
	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	mockClient.EXPECT().
		Initialize(gomock.Any(), gomock.Any()).
		Return(nil, deniedErr).
		Times(1)

	_, err := initializeEnclave(context.Background(), mockClient, newTestAwsCfg(t), testArns, false, testKeySource, logging.Get("test"))
	require.Error(t, err)
	require.ErrorIs(t, err, deniedErr)
	require.Contains(t, err.Error(), "non-retryable")
}

func TestInitializeEnclave_NonRetryableInvalidArgument(t *testing.T) {
	withFastBackoff(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	invalidErr := status.Error(codes.InvalidArgument, "session_token: value length must be at least 1 characters")
	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	mockClient.EXPECT().
		Initialize(gomock.Any(), gomock.Any()).
		Return(nil, invalidErr).
		Times(1)

	_, err := initializeEnclave(context.Background(), mockClient, newTestAwsCfg(t), testArns, false, testKeySource, logging.Get("test"))
	require.Error(t, err)
	require.ErrorIs(t, err, invalidErr)
	require.Contains(t, err.Error(), "non-retryable")
}

func TestInitializeEnclave_NonRetryableInternal(t *testing.T) {
	withFastBackoff(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	internalErr := status.Error(codes.Internal, "enclave Initialize crashed")
	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	mockClient.EXPECT().
		Initialize(gomock.Any(), gomock.Any()).
		Return(nil, internalErr).
		Times(1)

	// codes.Internal is not in the retryable list and not in the
	// explicit non-retryable-with-distinct-message list, so it falls
	// through to the default branch — single attempt, surface error.
	_, err := initializeEnclave(context.Background(), mockClient, newTestAwsCfg(t), testArns, false, testKeySource, logging.Get("test"))
	require.Error(t, err)
	require.ErrorIs(t, err, internalErr)
	require.Contains(t, err.Error(), "code=Internal")
}

// TestInitializeEnclave_CtxCancelledDuringBackoff exercises the
// ctx-aware sleep in the retry loop: with a non-zero backoff and a
// pre-cancelled ctx, the function must abort during the select instead
// of busy-looping or sleeping the full backoff. Uses a real
// initRetryBackoff so cancellation must beat the timer.
func TestInitializeEnclave_CtxCancelledDuringBackoff(t *testing.T) {
	saved := initRetryBackoff
	initRetryBackoff = 5 * time.Second // would dominate test duration if sleep was not ctx-aware
	t.Cleanup(func() { initRetryBackoff = saved })

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	unavailErr := status.Error(codes.Unavailable, "enclave not ready")
	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	// First Initialize attempt returns Unavailable, triggering the backoff.
	// Second attempt is never reached because ctx cancels during backoff.
	mockClient.EXPECT().Initialize(gomock.Any(), gomock.Any()).Return(nil, unavailErr).Times(1)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled so the select fires Done immediately on the first sleep

	start := time.Now()
	_, err := initializeEnclave(ctx, mockClient, newTestAwsCfg(t), testArns, false, testKeySource, logging.Get("test"))
	elapsed := time.Since(start)

	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, elapsed, initRetryBackoff,
		"ctx-aware sleep must abort before the timer fires")
}

func TestInitializeEnclave_TotalTimeoutEnforcedAcrossRetries(t *testing.T) {
	saved := initRetryBackoff
	initRetryBackoff = 5 * time.Second
	t.Cleanup(func() { initRetryBackoff = saved })

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	unavailErr := status.Error(codes.Unavailable, "enclave not ready")
	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	mockClient.EXPECT().Initialize(gomock.Any(), gomock.Any()).Return(nil, unavailErr).Times(1)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := initializeEnclave(ctx, mockClient, newTestAwsCfg(t), testArns, false, testKeySource, logging.Get("test"))

	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), initRetryBackoff)
}

func TestInitializeEnclave_CredentialsRetrieveError(t *testing.T) {
	withFastBackoff(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Mock not expected to be called — credential retrieval fails first.
	mockClient := enclaveProvider.NewMockEnclaveServiceClient(ctrl)

	awsCfg := aws.Config{
		Region:      "us-east-1",
		Credentials: failingCredentialProvider{},
	}

	_, err := initializeEnclave(context.Background(), mockClient, awsCfg, testArns, false, testKeySource, logging.Get("test"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "retrieve aws credentials")
}

// failingCredentialProvider is used by TestInitializeEnclave_CredentialsRetrieveError
// to force the early-exit path when the AWS SDK cannot mint credentials.
type failingCredentialProvider struct{}

func (failingCredentialProvider) Retrieve(_ context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, errors.New("imds unreachable")
}

type rotatingCredentialProvider struct {
	values        []aws.Credentials
	retrieveCalls int
}

func (p *rotatingCredentialProvider) Retrieve(_ context.Context) (aws.Credentials, error) {
	index := p.retrieveCalls
	p.retrieveCalls++
	if index >= len(p.values) {
		index = len(p.values) - 1
	}
	return p.values[index], nil
}
