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
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"
	"github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awskms"
	enclavePvd "github.com/circlefin/arc-remote-signer/internal/enclave/provider/enclave"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func newAtomicInitService(
	t *testing.T,
	nitro bool,
	pvd awskms.Provider,
	enclaveProvider enclavePvd.Provider,
) *Service {
	t.Helper()
	factory := func(context.Context, aws.Config, []string) (awskms.Provider, error) {
		return pvd, nil
	}
	return newServiceForTest(t, nitro, enclaveProvider, factory, "http://127.0.0.1:9000")
}

func generateInitRequest() *pb.InitializeRequest {
	req := validInitReq()
	req.KeySource = &pb.InitializeRequest_GenerateNew{
		GenerateNew: pb.Algorithm_ALGORITHM_ED25519,
	}
	return req
}

func TestInitialize_GeneratesAndInstallsKeyAtomically(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x11}, 32)
	var kmsCalls atomic.Int32
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			kmsCalls.Add(1)
			return dataKey, []byte("kms-ciphertext"), nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)

	resp, err := svc.Initialize(context.Background(), generateInitRequest())

	require.NoError(t, err)
	require.NotEmpty(t, resp.GetPublicKey())
	require.Equal(t, pb.Algorithm_ALGORITHM_ED25519, resp.GetSecretEnvelope().GetAlgorithm())
	signResp, err := svc.SignMessage(context.Background(), &pb.SignMessageRequest{Message: []byte("message")})
	require.NoError(t, err)
	valid, err := crypto.VerifySignedMessage(
		crypto.AlgorithmEd25519,
		signResp.GetSignature(),
		[]byte("message"),
		resp.GetPublicKey(),
	)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, int32(1), kmsCalls.Load(), "signing after Ready must not call KMS")
}

func TestInitialize_RecoversExistingKey(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x22}, 32)
	env, key := newEd25519Envelope(t, dataKey)
	wantPublicKey, err := key.PublicKey()
	require.NoError(t, err)
	var decryptCalls atomic.Int32
	pvd := &fakeKmsProvider{
		decrypt: func(context.Context, []byte) ([]byte, []byte, error) {
			decryptCalls.Add(1)
			return dataKey, nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)
	req := validInitReq()
	req.KeySource = &pb.InitializeRequest_ExistingKey{ExistingKey: env}

	resp, err := svc.Initialize(context.Background(), req)

	require.NoError(t, err)
	require.Equal(t, wantPublicKey, resp.GetPublicKey())
	require.Nil(t, resp.GetSecretEnvelope())
	_, err = svc.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{})
	require.NoError(t, err)
	require.Equal(t, int32(1), decryptCalls.Load())
}

func TestInitialize_MapsDecryptKMSError(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x24}, 32)
	env, _ := newEd25519Envelope(t, dataKey)
	kmsErr := &smithy.GenericAPIError{
		Code:    "AccessDeniedException",
		Message: "policy denied the request",
	}
	pvd := &fakeKmsProvider{
		decrypt: func(context.Context, []byte) ([]byte, []byte, error) {
			return nil, nil, kmsErr
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)
	req := validInitReq()
	req.KeySource = &pb.InitializeRequest_ExistingKey{ExistingKey: env}

	resp, err := svc.Initialize(context.Background(), req)

	require.Nil(t, resp)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "kms decrypt data key")
}

func TestInitialize_FailureDoesNotPublishReadyAndCanRetry(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x33}, 32)
	recipientCiphertext := []byte("recipient-ciphertext")
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			return nil, []byte("kms-ciphertext"), recipientCiphertext, nil
		},
	}
	ctrl := gomock.NewController(t)
	enclaveProvider := enclavePvd.NewMockProvider(ctrl)
	enclaveProvider.EXPECT().DecryptKMSEnvelopedKey(recipientCiphertext).Return(dataKey, nil).Times(2)
	enclaveProvider.EXPECT().Attest(gomock.Any()).Return(nil, errors.New("attestation failed"))
	enclaveProvider.EXPECT().Attest(gomock.Any()).Return([]byte("attestation"), nil)
	svc := newAtomicInitService(t, true, pvd, enclaveProvider)

	resp, err := svc.Initialize(context.Background(), generateInitRequest())
	require.Nil(t, resp)
	require.Equal(t, codes.Internal, status.Code(err))
	signResp, signErr := svc.SignMessage(
		context.Background(),
		&pb.SignMessageRequest{Message: []byte("message")},
	)
	require.Nil(t, signResp)
	require.Equal(t, codes.FailedPrecondition, status.Code(signErr))

	resp, err = svc.Initialize(context.Background(), generateInitRequest())
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetPublicKey())
	require.Equal(t, []byte("attestation"), resp.GetAttestationDocument())
}

func TestInitialize_RetryCreatesAttemptScopedProviderAndPublishesOnlySuccess(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x34}, 32)
	providers := []*fakeKmsProvider{
		{
			generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
				return nil, nil, nil, &smithy.GenericAPIError{
					Code:    "ExpiredTokenException",
					Message: "expired",
				}
			},
		},
		{
			generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
				return dataKey, []byte("kms-ciphertext"), nil, nil
			},
		},
	}
	var factoryCalls atomic.Int32
	factory := func(context.Context, aws.Config, []string) (awskms.Provider, error) {
		index := int(factoryCalls.Add(1) - 1)
		return providers[index], nil
	}
	svc := newServiceForTest(t, false, nil, factory, "http://127.0.0.1:9000")

	resp, err := svc.Initialize(context.Background(), generateInitRequest())

	require.Nil(t, resp)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	require.False(t, svc.gate.initialized())
	require.Nil(t, svc.gate.state())

	resp, err = svc.Initialize(context.Background(), generateInitRequest())

	require.NoError(t, err)
	require.NotEmpty(t, resp.GetPublicKey())
	require.True(t, svc.gate.initialized())
	require.Equal(t, int32(2), factoryCalls.Load())
}

func TestInitialize_GeneratesAndInstallsBLSKey(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x44}, 32)
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			return dataKey, []byte("kms-ciphertext"), nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)
	req := validInitReq()
	req.KeySource = &pb.InitializeRequest_GenerateNew{GenerateNew: pb.Algorithm_ALGORITHM_BLS}

	resp, err := svc.Initialize(context.Background(), req)

	require.NoError(t, err)
	require.Equal(t, pb.Algorithm_ALGORITHM_BLS, resp.GetSecretEnvelope().GetAlgorithm())
	signResp, err := svc.SignMessage(
		context.Background(),
		&pb.SignMessageRequest{Message: []byte("message")},
	)
	require.NoError(t, err)
	valid, err := crypto.VerifySignedMessage(
		crypto.AlgorithmBLS,
		signResp.GetSignature(),
		[]byte("message"),
		resp.GetPublicKey(),
	)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestInitialize_GeneratedEnvelopeReplaysAsExistingSource(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x55}, 32)
	var generateCalls atomic.Int32
	var decryptCalls atomic.Int32
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			generateCalls.Add(1)
			return dataKey, []byte("kms-ciphertext"), nil, nil
		},
		decrypt: func(context.Context, []byte) ([]byte, []byte, error) {
			decryptCalls.Add(1)
			return dataKey, nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)

	generated, err := svc.Initialize(context.Background(), generateInitRequest())
	require.NoError(t, err)
	recoveryReq := validInitReq()
	recoveryReq.KeySource = &pb.InitializeRequest_ExistingKey{
		ExistingKey: proto.Clone(generated.GetSecretEnvelope()).(*pb.SecretEnvelope),
	}

	recovered, err := svc.Initialize(context.Background(), recoveryReq)

	require.NoError(t, err)
	require.Equal(t, generated.GetPublicKey(), recovered.GetPublicKey())
	require.Nil(t, recovered.GetSecretEnvelope())
	require.Equal(t, int32(1), generateCalls.Load())
	require.Equal(t, int32(0), decryptCalls.Load(), "host restart replay must use the installed key")
}

func TestInitialize_GeneratedEnvelopeRejectsDifferentExistingSource(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x56}, 32)
	var generateCalls atomic.Int32
	var decryptCalls atomic.Int32
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			generateCalls.Add(1)
			return dataKey, []byte("kms-ciphertext"), nil, nil
		},
		decrypt: func(context.Context, []byte) ([]byte, []byte, error) {
			decryptCalls.Add(1)
			return dataKey, nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)

	generated, err := svc.Initialize(context.Background(), generateInitRequest())
	require.NoError(t, err)
	differentEnvelope := proto.Clone(generated.GetSecretEnvelope()).(*pb.SecretEnvelope)
	differentEnvelope.Nonce[0] ^= 0xff
	conflictReq := validInitReq()
	conflictReq.KeySource = &pb.InitializeRequest_ExistingKey{ExistingKey: differentEnvelope}

	resp, err := svc.Initialize(context.Background(), conflictReq)

	require.Nil(t, resp)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, int32(1), generateCalls.Load())
	require.Equal(t, int32(0), decryptCalls.Load())
}

func TestInitialize_ConflictingKeySourceAfterReadyFailsWithoutKMS(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x66}, 32)
	var kmsCalls atomic.Int32
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			kmsCalls.Add(1)
			return dataKey, []byte("kms-ciphertext"), nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)
	_, err := svc.Initialize(context.Background(), generateInitRequest())
	require.NoError(t, err)
	conflict := validInitReq()
	conflict.KeySource = &pb.InitializeRequest_GenerateNew{GenerateNew: pb.Algorithm_ALGORITHM_BLS}

	resp, err := svc.Initialize(context.Background(), conflict)

	require.Nil(t, resp)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, int32(1), kmsCalls.Load())
}

func TestInitialize_ResponseReplayIsImmutable(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x77}, 32)
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			return dataKey, []byte("kms-ciphertext"), nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)
	req := generateInitRequest()
	first, err := svc.Initialize(context.Background(), req)
	require.NoError(t, err)
	wantReplay := proto.Clone(first).(*pb.InitializeResponse)
	first.PublicKey[0] ^= 0xff
	first.SecretEnvelope.Nonce[0] ^= 0xff

	replayed, err := svc.Initialize(
		context.Background(),
		proto.Clone(req).(*pb.InitializeRequest),
	)

	require.NoError(t, err)
	require.True(t, proto.Equal(wantReplay, replayed))
}

func TestInitialize_ConcurrentDifferentSourcesPublishOneWinner(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x88}, 32)
	started := make(chan struct{})
	release := make(chan struct{})
	var kmsCalls atomic.Int32
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			if kmsCalls.Add(1) == 1 {
				close(started)
			}
			<-release
			return dataKey, []byte("kms-ciphertext"), nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)
	requests := []*pb.InitializeRequest{generateInitRequest(), validInitReq()}
	requests[1].KeySource = &pb.InitializeRequest_GenerateNew{
		GenerateNew: pb.Algorithm_ALGORITHM_BLS,
	}
	waiting := make(chan struct{})
	waitingContext := &observedDoneContext{
		Context:  context.Background(),
		observed: waiting,
	}
	responses := make([]*pb.InitializeResponse, len(requests))
	errs := make([]error, len(requests))
	var waitGroup sync.WaitGroup
	waitGroup.Add(len(requests))
	go func() {
		defer waitGroup.Done()
		responses[0], errs[0] = svc.Initialize(context.Background(), requests[0])
	}()
	<-started
	go func() {
		defer waitGroup.Done()
		responses[1], errs[1] = svc.Initialize(waitingContext, requests[1])
	}()
	<-waiting
	close(release)
	waitGroup.Wait()

	var successCount, conflictCount int
	for i := range requests {
		switch status.Code(errs[i]) {
		case codes.OK:
			successCount++
			require.NotEmpty(t, responses[i].GetPublicKey())
		case codes.FailedPrecondition:
			conflictCount++
			require.Nil(t, responses[i])
		default:
			require.Failf(t, "unexpected result", "request %d returned %v", i, errs[i])
		}
	}
	require.Equal(t, 1, successCount)
	require.Equal(t, 1, conflictCount)
	require.Equal(t, int32(1), kmsCalls.Load())
}

func TestInitialize_RequiresExactlyOneValidKeySource(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x99}, 32)
	var kmsCalls atomic.Int32
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			kmsCalls.Add(1)
			return dataKey, []byte("kms-ciphertext"), nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)

	tests := map[string]*pb.InitializeRequest{
		"missing source": func() *pb.InitializeRequest {
			req := validInitReq()
			req.KeySource = nil
			return req
		}(),
		"unspecified generate algorithm": func() *pb.InitializeRequest {
			req := validInitReq()
			req.KeySource = &pb.InitializeRequest_GenerateNew{
				GenerateNew: pb.Algorithm_ALGORITHM_UNSPECIFIED,
			}
			return req
		}(),
		"incomplete existing envelope": func() *pb.InitializeRequest {
			req := validInitReq()
			req.KeySource = &pb.InitializeRequest_ExistingKey{
				ExistingKey: &pb.SecretEnvelope{Algorithm: pb.Algorithm_ALGORITHM_ED25519},
			}
			return req
		}(),
	}

	for name, req := range tests {
		t.Run(name, func(t *testing.T) {
			resp, err := svc.Initialize(context.Background(), req)
			require.Nil(t, resp)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
	require.Equal(t, int32(0), kmsCalls.Load())
}

type observedDoneContext struct {
	context.Context
	once     sync.Once
	observed chan struct{}
}

func (c *observedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() {
		close(c.observed)
	})
	return nil
}
