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

func TestInitialize_GenerateNewSupportsBothAlgorithms(t *testing.T) {
	tests := []struct {
		name      string
		algorithm pb.Algorithm
	}{
		{name: "Ed25519", algorithm: pb.Algorithm_ALGORITHM_ED25519},
		{name: "BLS", algorithm: pb.Algorithm_ALGORITHM_BLS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataKey := bytes.Repeat([]byte{0x11}, 32)
			var kmsCalls atomic.Int32
			pvd := &fakeKmsProvider{
				generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
					kmsCalls.Add(1)
					return dataKey, []byte("kms-ciphertext"), nil, nil
				},
			}
			svc := newAtomicInitService(t, false, pvd, nil)
			req := validInitReq()
			req.KeySource = &pb.InitializeRequest_GenerateNew{GenerateNew: tt.algorithm}

			resp, err := svc.Initialize(context.Background(), req)

			require.NoError(t, err)
			require.NotEmpty(t, resp.GetPublicKey())
			require.Empty(t, resp.GetAttestationDocument())
			require.Equal(t, tt.algorithm, resp.GetSecretEnvelope().GetAlgorithm())
			require.NotEmpty(t, resp.GetSecretEnvelope().GetEncryptedPrivateKey())
			require.NotEmpty(t, resp.GetSecretEnvelope().GetNonce())
			require.Equal(t, int32(1), kmsCalls.Load())
		})
	}
}

func TestInitialize_LoadExistingReturnsPublicKeyWithoutEnvelope(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x22}, 32)
	env, secretKey := newEd25519Envelope(t, dataKey)
	wantPublicKey, err := secretKey.PublicKey()
	require.NoError(t, err)
	var generateCalls atomic.Int32
	var decryptCalls atomic.Int32
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			generateCalls.Add(1)
			return dataKey, []byte("probe"), nil, nil
		},
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
	replayed, err := svc.Initialize(context.Background(), proto.Clone(req).(*pb.InitializeRequest))
	require.NoError(t, err)
	require.True(t, proto.Equal(resp, replayed))

	publicKeyResp, err := svc.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{})
	require.NoError(t, err)
	require.Equal(t, wantPublicKey, publicKeyResp.GetPublicKey())

	message := []byte("message")
	signResp, err := svc.SignMessage(context.Background(), &pb.SignMessageRequest{Message: message})
	require.NoError(t, err)
	valid, err := crypto.VerifySignedMessage(
		crypto.AlgorithmEd25519,
		signResp.GetSignature(),
		message,
		wantPublicKey,
	)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, int32(0), generateCalls.Load())
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

	resp, err := svc.Initialize(context.Background(), validInitReq())

	require.Nil(t, resp)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	require.False(t, svc.gate.initialized())
	require.Nil(t, svc.gate.state())

	resp, err = svc.Initialize(context.Background(), validInitReq())

	require.NoError(t, err)
	require.NotEmpty(t, resp.GetPublicKey())
	require.True(t, svc.gate.initialized())
	require.Equal(t, int32(2), factoryCalls.Load())
}

func TestReadyState_ServesReadAndSignWithoutKMS(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x23}, 32)
	var kmsCalls atomic.Int32
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			kmsCalls.Add(1)
			return dataKey, []byte("kms-ciphertext"), nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)
	initResp, err := svc.Initialize(context.Background(), validInitReq())
	require.NoError(t, err)
	require.Equal(t, int32(1), kmsCalls.Load())

	publicKeyResp, err := svc.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{})
	require.NoError(t, err)
	require.Equal(t, initResp.PublicKey, publicKeyResp.PublicKey)

	message := []byte("message")
	signResp, err := svc.SignMessage(context.Background(), &pb.SignMessageRequest{Message: message})
	require.NoError(t, err)
	require.NotEmpty(t, signResp.Signature)
	valid, err := crypto.VerifySignedMessage(
		crypto.AlgorithmEd25519,
		signResp.Signature,
		message,
		initResp.PublicKey,
	)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, int32(1), kmsCalls.Load())
}

func TestReadyState_RejectsReadAndSignBeforeInitialize(t *testing.T) {
	svc := newAtomicInitService(t, false, &fakeKmsProvider{}, nil)

	publicKeyResp, publicKeyErr := svc.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{})
	signResp, signErr := svc.SignMessage(
		context.Background(),
		&pb.SignMessageRequest{Message: []byte("message")},
	)

	require.Nil(t, publicKeyResp)
	require.Equal(t, codes.FailedPrecondition, status.Code(publicKeyErr))
	require.Nil(t, signResp)
	require.Equal(t, codes.FailedPrecondition, status.Code(signErr))
}

func TestGenerateKey_DisabledAfterAtomicInitialization(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x24}, 32)
	var kmsCalls atomic.Int32
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			kmsCalls.Add(1)
			return dataKey, []byte("kms-ciphertext"), nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)
	_, err := svc.Initialize(context.Background(), validInitReq())
	require.NoError(t, err)

	resp, err := svc.GenerateKey(
		context.Background(),
		&pb.GenerateKeyRequest{Algorithm: pb.Algorithm_ALGORITHM_ED25519},
	)

	require.Nil(t, resp)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, int32(1), kmsCalls.Load())
}

func TestInitialize_SameSourceReplaysStoredResult(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x33}, 32)
	var kmsCalls atomic.Int32
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			kmsCalls.Add(1)
			return dataKey, []byte("kms-ciphertext"), nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)
	req := validInitReq()

	first, err := svc.Initialize(context.Background(), req)
	require.NoError(t, err)
	wantReplay := proto.Clone(first)
	first.PublicKey[0] ^= 0xff
	first.SecretEnvelope.Nonce[0] ^= 0xff
	second, err := svc.Initialize(context.Background(), proto.Clone(req).(*pb.InitializeRequest))

	require.NoError(t, err)
	require.True(t, proto.Equal(wantReplay, second))
	require.NotEmpty(t, second.GetPublicKey())
	require.Equal(t, int32(1), kmsCalls.Load())
}

func TestInitialize_GeneratedEnvelopeReplaysAsExistingSource(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x34}, 32)
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

	generated, err := svc.Initialize(context.Background(), validInitReq())
	require.NoError(t, err)
	recoveryReq := validInitReq()
	recoveryReq.KeySource = &pb.InitializeRequest_ExistingKey{
		ExistingKey: proto.Clone(generated.GetSecretEnvelope()).(*pb.SecretEnvelope),
	}

	recovered, err := svc.Initialize(context.Background(), recoveryReq)

	require.NoError(t, err)
	require.Equal(t, generated.GetPublicKey(), recovered.GetPublicKey())
	require.Equal(t, generated.GetAttestationDocument(), recovered.GetAttestationDocument())
	require.Nil(t, recovered.GetSecretEnvelope())
	require.Equal(t, int32(1), generateCalls.Load())
	require.Equal(t, int32(0), decryptCalls.Load())
}

func TestInitialize_GeneratedEnvelopeRejectsDifferentExistingSource(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x35}, 32)
	var kmsCalls atomic.Int32
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			kmsCalls.Add(1)
			return dataKey, []byte("kms-ciphertext"), nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)

	generated, err := svc.Initialize(context.Background(), validInitReq())
	require.NoError(t, err)
	differentEnvelope := proto.Clone(generated.GetSecretEnvelope()).(*pb.SecretEnvelope)
	differentEnvelope.Nonce[0] ^= 0xff
	conflictReq := validInitReq()
	conflictReq.KeySource = &pb.InitializeRequest_ExistingKey{ExistingKey: differentEnvelope}

	resp, err := svc.Initialize(context.Background(), conflictReq)

	require.Nil(t, resp)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, int32(1), kmsCalls.Load())
}

func TestInitialize_ConflictingSourceAfterReadyDoesNotCallKMS(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x44}, 32)
	var kmsCalls atomic.Int32
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			kmsCalls.Add(1)
			return dataKey, []byte("kms-ciphertext"), nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)
	first := validInitReq()
	_, err := svc.Initialize(context.Background(), first)
	require.NoError(t, err)

	conflict := validInitReq()
	conflict.KeySource = &pb.InitializeRequest_GenerateNew{GenerateNew: pb.Algorithm_ALGORITHM_BLS}
	resp, err := svc.Initialize(context.Background(), conflict)

	require.Nil(t, resp)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, int32(1), kmsCalls.Load())
}

func TestInitialize_ConcurrentSourcesPublishOneWinner(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x55}, 32)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			if calls.Add(1) == 1 {
				close(started)
			}
			<-release
			return dataKey, []byte("kms-ciphertext"), nil, nil
		},
	}
	svc := newAtomicInitService(t, false, pvd, nil)
	requests := []*pb.InitializeRequest{validInitReq(), validInitReq()}
	requests[1].KeySource = &pb.InitializeRequest_GenerateNew{GenerateNew: pb.Algorithm_ALGORITHM_BLS}
	waiting := make(chan struct{})
	waitingContext := &observedDoneContext{
		Context:  context.Background(),
		observed: waiting,
	}

	var wg sync.WaitGroup
	wg.Add(2)
	responses := make([]*pb.InitializeResponse, len(requests))
	errs := make([]error, len(requests))
	go func() {
		defer wg.Done()
		responses[0], errs[0] = svc.Initialize(context.Background(), requests[0])
	}()
	<-started
	go func() {
		defer wg.Done()
		responses[1], errs[1] = svc.Initialize(waitingContext, requests[1])
	}()
	<-waiting
	close(release)
	wg.Wait()

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
	require.Equal(t, int32(1), calls.Load())
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

func TestInitialize_AttestationFailureLeavesGateEmpty(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x66}, 32)
	recipientCiphertext := []byte("recipient-ciphertext")
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			return nil, []byte("kms-ciphertext"), recipientCiphertext, nil
		},
	}
	ctrl := gomock.NewController(t)
	enclaveProvider := enclavePvd.NewMockProvider(ctrl)
	gomock.InOrder(
		enclaveProvider.EXPECT().DecryptKMSEnvelopedKey(recipientCiphertext).Return(dataKey, nil),
		enclaveProvider.EXPECT().Attest(gomock.Any()).Return(nil, errors.New("attestation failed")),
		enclaveProvider.EXPECT().DecryptKMSEnvelopedKey(recipientCiphertext).Return(dataKey, nil),
		enclaveProvider.EXPECT().Attest(gomock.Any()).Return([]byte("attestation-document"), nil),
	)
	svc := newAtomicInitService(t, true, pvd, enclaveProvider)

	resp, err := svc.Initialize(context.Background(), validInitReq())

	require.Nil(t, resp)
	require.Equal(t, codes.Internal, status.Code(err))
	require.False(t, svc.gate.initialized())
	require.Nil(t, svc.gate.state())

	resp, err = svc.Initialize(context.Background(), validInitReq())

	require.NoError(t, err)
	require.Equal(t, []byte("attestation-document"), resp.GetAttestationDocument())
	require.True(t, svc.gate.initialized())
}

func TestInitialize_RequiresExactlyOneValidKeySource(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x77}, 32)
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
