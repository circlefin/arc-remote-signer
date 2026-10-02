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
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awskms"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/enclave"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/stretchr/testify/require"
)

// fakeKmsProvider implements awskms.Provider for enclave-side tests.
// We deliberately do not use the gomock generated under
// internal/enclave/provider/awskms/awskms_mock.go to keep these tests
// decoupled from the generated mock.
type fakeKmsProvider struct {
	generateDataKey func(ctx context.Context) ([]byte, []byte, []byte, error)
	decrypt         func(ctx context.Context, ciphertext []byte) ([]byte, []byte, error)
}

func (f *fakeKmsProvider) GenerateDataKey(ctx context.Context) ([]byte, []byte, []byte, error) {
	return f.generateDataKey(ctx)
}

func (f *fakeKmsProvider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, []byte, error) {
	return f.decrypt(ctx, ciphertext)
}

// newServiceForTest builds a Service whose gate runs the real runInit
// method, with an injectable KMS factory and awsproxy endpoint. Test-only.
func newServiceForTest(
	t *testing.T,
	nitroEnclaveEnabled bool,
	enclavePvd enclave.Provider,
	factory awskms.Factory,
	awsproxyEndpoint string,
) *Service {
	t.Helper()
	s := &Service{
		nitroEnclaveEnabled: nitroEnclaveEnabled,
		enclavePvd:          enclavePvd,
		kmsFactory:          factory,
		awsproxyEndpoint:    awsproxyEndpoint,
	}
	s.gate = newInitGate(s.runInit)
	return s
}

// validInitReq returns a well-formed Initialize request shape for tests.
func validInitReq() *pb.InitializeRequest {
	return &pb.InitializeRequest{
		Credentials: &pb.AwsCredentials{
			AccessKeyId:     "AKIA-test",
			SecretAccessKey: "secret",
			SessionToken:    "session",
			Region:          "us-east-1",
		},
		KmsKeyArns: []string{"arn:aws:kms:us-east-1:123456789012:key/abc"},
		KeySource: &pb.InitializeRequest_GenerateNew{
			GenerateNew: pb.Algorithm_ALGORITHM_ED25519,
		},
	}
}

func TestNewRunInit_HappyPath(t *testing.T) {
	type ctxKey struct{}
	var calledArns []string
	var calledRegion string
	var calledCtxValue any
	factory := func(callCtx context.Context, awsCfg aws.Config, arns []string) (awskms.Provider, error) {
		calledArns = arns
		calledRegion = awsCfg.Region
		calledCtxValue = callCtx.Value(ctxKey{})
		return &fakeKmsProvider{
			generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
				return bytes.Repeat([]byte{0x11}, 32), []byte("cipher"), []byte("recipient"), nil
			},
		}, nil
	}

	s := newServiceForTest(t, false, nil, factory, "http://127.0.0.1:9000")
	ctx := context.WithValue(context.Background(), ctxKey{}, "marker")
	_, err := s.runInit(ctx, validInitReq())
	require.NoError(t, err)
	require.Equal(t, []string{"arn:aws:kms:us-east-1:123456789012:key/abc"}, calledArns)
	require.Equal(t, "us-east-1", calledRegion)
	require.Equal(t, "marker", calledCtxValue,
		"factory must receive the runInit per-call ctx (carries deadline + values)")
}

func TestRunInitSelectsKMSBackend(t *testing.T) {
	tests := map[string]struct {
		localstack bool
		wantBase   string
	}{
		"LocalStack": {localstack: true, wantBase: "http://127.0.0.1:9000"},
		"AWS KMS":    {},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var gotBase string
			factory := func(_ context.Context, awsCfg aws.Config, _ []string) (awskms.Provider, error) {
				if awsCfg.BaseEndpoint != nil {
					gotBase = *awsCfg.BaseEndpoint
				}
				return &fakeKmsProvider{
					generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
						return bytes.Repeat([]byte{0x11}, 32), []byte("cipher"), nil, nil
					},
				}, nil
			}
			svc := newServiceForTest(
				t,
				false,
				nil,
				factory,
				"http://127.0.0.1:9000",
			)
			req := validInitReq()
			req.KmsLocalstackEnabled = tt.localstack

			_, err := svc.runInit(context.Background(), req)
			require.NoError(t, err)
			require.Equal(t, tt.wantBase, gotBase)
		})
	}
}

func TestNewRunInit_BuildConfigError_NilCreds(t *testing.T) {
	factory := func(_ context.Context, _ aws.Config, _ []string) (awskms.Provider, error) {
		t.Fatal("factory must not be called when awskms.BuildConfig fails")
		return nil, nil
	}
	s := newServiceForTest(t, false, nil, factory, "http://127.0.0.1:9000")
	req := &pb.InitializeRequest{Credentials: nil, KmsKeyArns: []string{"arn"}}
	_, err := s.runInit(context.Background(), req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "build aws config")
}

func TestNewRunInit_BuildConfigError_EmptyEndpoint(t *testing.T) {
	factory := func(_ context.Context, _ aws.Config, _ []string) (awskms.Provider, error) {
		t.Fatal("factory must not be called when awskms.BuildConfig fails")
		return nil, nil
	}
	s := newServiceForTest(t, false, nil, factory, "")
	_, err := s.runInit(context.Background(), validInitReq())
	require.Error(t, err)
	require.Contains(t, err.Error(), "build aws config")
}

func TestNewRunInit_FactoryError(t *testing.T) {
	wantErr := errors.New("factory boom")
	factory := func(_ context.Context, _ aws.Config, _ []string) (awskms.Provider, error) {
		return nil, wantErr
	}
	s := newServiceForTest(t, false, nil, factory, "http://127.0.0.1:9000")
	_, err := s.runInit(context.Background(), validInitReq())
	require.Error(t, err)
	require.ErrorIs(t, err, wantErr)
	require.Contains(t, err.Error(), "build kms provider")
}

func TestNewRunInit_GenerateDataKeyError_PassThrough(t *testing.T) {
	// Tests that runInit returns the raw SDK error; mapping to gRPC code
	// happens later in runInitStatusError, not inside runInit.
	kmsErr := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}
	factory := func(_ context.Context, _ aws.Config, _ []string) (awskms.Provider, error) {
		return &fakeKmsProvider{
			generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
				return nil, nil, nil, kmsErr
			},
		}, nil
	}
	s := newServiceForTest(t, false, nil, factory, "http://127.0.0.1:9000")
	_, err := s.runInit(context.Background(), validInitReq())
	require.ErrorIs(t, err, kmsErr)
}

func TestNewRunInit_ContextCancelled(t *testing.T) {
	factory := func(_ context.Context, _ aws.Config, _ []string) (awskms.Provider, error) {
		return &fakeKmsProvider{
			generateDataKey: func(ctx context.Context) ([]byte, []byte, []byte, error) {
				<-ctx.Done()
				return nil, nil, nil, ctx.Err()
			},
		}, nil
	}
	s := newServiceForTest(t, false, nil, factory, "http://127.0.0.1:9000")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled
	_, err := s.runInit(ctx, validInitReq())
	require.ErrorIs(t, err, context.Canceled)
}

func TestRunInit_RetainsKMSProvider(t *testing.T) {
	want := &fakeKmsProvider{
		generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
			return bytes.Repeat([]byte{0x11}, 32), []byte("cipher"), []byte("recipient"), nil
		},
	}
	factory := func(_ context.Context, _ aws.Config, _ []string) (awskms.Provider, error) {
		return want, nil
	}
	s := newServiceForTest(t, false, nil, factory, "http://127.0.0.1:9000")
	_, err := s.Initialize(context.Background(), validInitReq())
	require.NoError(t, err)
}
