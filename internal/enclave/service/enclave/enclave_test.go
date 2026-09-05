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
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	enclaveCrypto "github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awskms"
	enclavePvd "github.com/circlefin/arc-remote-signer/internal/enclave/provider/enclave"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// EnclaveServiceTestSuite covers request validation, the Initialize gate, and
// the pure helpers. The SecretEnvelope generate/read data paths (KMS decrypt,
// caching, Nitro in-process RSA decrypt) are covered in envelope_test.go against the
// fakeKmsProvider seam.
type EnclaveServiceTestSuite struct {
	suite.Suite
	ctrl    *gomock.Controller
	enclave *enclavePvd.MockProvider
	service *Service
}

func (s *EnclaveServiceTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.enclave = enclavePvd.NewMockProvider(s.ctrl)

	s.service = New(false, s.enclave, nil, "")
}

func (s *EnclaveServiceTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *EnclaveServiceTestSuite) TestGenerateKey_NilRequest() {
	resp, err := s.service.GenerateKey(context.Background(), nil)

	s.Nil(resp)
	s.Error(err)
	s.Equal(codes.InvalidArgument, status.Code(err))
	s.Contains(err.Error(), "request is nil")
}

func (s *EnclaveServiceTestSuite) TestGenerateKey_InvalidAlgorithm() {
	resp, err := s.service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		Algorithm: pb.Algorithm_ALGORITHM_UNSPECIFIED,
	})

	s.Nil(resp)
	s.Error(err)
	s.Equal(codes.InvalidArgument, status.Code(err))
}

func (s *EnclaveServiceTestSuite) TestToAlgorithm() {
	tests := []struct {
		name      string
		input     pb.Algorithm
		wantAlg   enclaveCrypto.Algorithm
		wantError bool
	}{
		{"bls maps correctly", pb.Algorithm_ALGORITHM_BLS, enclaveCrypto.AlgorithmBLS, false},
		{"ed25519 maps correctly", pb.Algorithm_ALGORITHM_ED25519, enclaveCrypto.AlgorithmEd25519, false},
		{"unspecified returns error", pb.Algorithm_ALGORITHM_UNSPECIFIED, enclaveCrypto.Algorithm(""), true},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			alg, err := toAlgorithm(tt.input)
			if tt.wantError {
				s.Error(err)
			} else {
				s.NoError(err)
			}
			s.Equal(tt.wantAlg, alg)
		})
	}
}

// validInitReq is the request shape Initialize tests use when they need a
// well-formed payload. The credentials values are irrelevant — the
// runInit callbacks injected by these tests do not actually call AWS.
// KmsKeyArn must parse via aws-sdk arn.Parse to clear Service.Initialize's
// sanity check; the value is a syntactically valid ARN, never dialed.
func (s *EnclaveServiceTestSuite) validInitReq() *pb.InitializeRequest {
	s.T().Helper()
	return &pb.InitializeRequest{
		Credentials: &pb.AwsCredentials{
			AccessKeyId:     "AKIA-test",
			SecretAccessKey: "secret",
			SessionToken:    "session",
			Region:          "us-east-1",
		},
		KmsKeyArns: []string{"arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000"},
		KeySource: &pb.InitializeRequest_GenerateNew{
			GenerateNew: pb.Algorithm_ALGORITHM_ED25519,
		},
	}
}

// newUninitializedService builds a fresh Service with the given runInit
// callback. Init-gate tests use this so they can inject failing or
// instrumented callbacks; the suite-level s.service is sufficient for
// tests that do not care about the gate's runInit behaviour.
func (s *EnclaveServiceTestSuite) newUninitializedService(
	runInit func(context.Context, *pb.InitializeRequest) error,
) *Service {
	s.T().Helper()
	return newWithGate(false, s.enclave, runInit)
}

// TestInitialize_RequestValidation covers the synchronous validation
// errors that fire before the init gate runs.
func (s *EnclaveServiceTestSuite) TestInitialize_RequestValidation() {
	svc := s.newUninitializedService(func(context.Context, *pb.InitializeRequest) error {
		s.FailNow("runInit must not be called when request validation fails")
		return nil
	})

	validCreds := &pb.AwsCredentials{
		AccessKeyId:     "AKIA-test",
		SecretAccessKey: "secret",
		SessionToken:    "session",
		Region:          "us-east-1",
	}

	tests := map[string]struct {
		req      *pb.InitializeRequest
		wantCode codes.Code
	}{
		"NilReq":         {req: nil, wantCode: codes.InvalidArgument},
		"NilCredentials": {req: &pb.InitializeRequest{Credentials: nil}, wantCode: codes.InvalidArgument},
		"NilArns": {
			// Defense-in-depth against in-process callers bypassing protovalidate
			// (which enforces min_items=1 at the wire boundary).
			req:      &pb.InitializeRequest{Credentials: validCreds, KmsKeyArns: nil},
			wantCode: codes.InvalidArgument,
		},
		"EmptyArnList": {
			req:      &pb.InitializeRequest{Credentials: validCreds, KmsKeyArns: []string{}},
			wantCode: codes.InvalidArgument,
		},
		// MalformedArn covers the reviewer-flagged path (PR #299 review
		// thread): arn.Parse rejects "not-an-arn", handler short-circuits
		// with InvalidArgument rather than falling through to the KMS
		// factory and surfacing as Internal.
		"MalformedArn": {
			req:      &pb.InitializeRequest{Credentials: validCreds, KmsKeyArns: []string{"not-an-arn"}},
			wantCode: codes.InvalidArgument,
		},
		"EmptyArnInList": {
			req:      &pb.InitializeRequest{Credentials: validCreds, KmsKeyArns: []string{""}},
			wantCode: codes.InvalidArgument,
		},
		"SecondArnMalformed": {
			// First ARN parses fine, second fails — loop must check every entry.
			req: &pb.InitializeRequest{
				Credentials: validCreds,
				KmsKeyArns: []string{
					"arn:aws:kms:us-east-1:000000000000:key/abc",
					"not-an-arn",
				},
			},
			wantCode: codes.InvalidArgument,
		},
	}
	for name, tt := range tests {
		s.Run(name, func() {
			resp, err := svc.Initialize(context.Background(), tt.req)
			s.Require().Error(err)
			s.Nil(resp)
			st, ok := status.FromError(err)
			s.Require().True(ok)
			s.Equal(tt.wantCode, st.Code())
			s.False(svc.gate.initialized(), "gate must not latch when validation fails")
		})
	}
}

// TestInitialize_HappyPath verifies a single successful Initialize call
// latches the gate and returns an empty response.
func (s *EnclaveServiceTestSuite) TestInitialize_HappyPath() {
	var calls atomic.Int32
	svc := s.newUninitializedService(func(context.Context, *pb.InitializeRequest) error {
		calls.Add(1)
		return nil
	})

	resp, err := svc.Initialize(context.Background(), s.validInitReq())
	s.Require().NoError(err)
	s.NotNil(resp)
	s.True(svc.gate.initialized(), "gate must latch after successful Initialize")
	s.Equal(int32(1), calls.Load(), "runInit must run exactly once")
}

func (s *EnclaveServiceTestSuite) TestInitialize_NitroRejectsLocalstack() {
	var called atomic.Bool
	svc := newWithGate(true, s.enclave, func(context.Context, *pb.InitializeRequest) error {
		called.Store(true)
		return nil
	})
	req := s.validInitReq()
	req.KmsLocalstackEnabled = true

	resp, err := svc.Initialize(context.Background(), req)

	s.Nil(resp)
	s.Equal(codes.InvalidArgument, status.Code(err))
	s.False(called.Load(), "runInit must not run for LocalStack in Nitro mode")
}

// TestInitialize_MultipleArnsAllValid verifies the ARN-validation loop
// clears a multi-region ARN slice (every entry parses) and the request
// flows through to runInit unchanged.
func (s *EnclaveServiceTestSuite) TestInitialize_MultipleArnsAllValid() {
	var capturedArns []string
	svc := s.newUninitializedService(func(_ context.Context, req *pb.InitializeRequest) error {
		capturedArns = req.KmsKeyArns
		return nil
	})

	req := s.validInitReq()
	req.KmsKeyArns = []string{
		"arn:aws:kms:us-east-1:000000000000:key/abc",
		"arn:aws:kms:us-west-2:000000000000:key/def",
	}

	resp, err := svc.Initialize(context.Background(), req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(req.KmsKeyArns, capturedArns, "runInit must observe the full ARN slice unchanged")
}

// TestInitialize_Idempotent verifies a repeated Initialize call after a
// successful one returns OK without invoking runInit again.
func (s *EnclaveServiceTestSuite) TestInitialize_Idempotent() {
	var calls atomic.Int32
	svc := s.newUninitializedService(func(context.Context, *pb.InitializeRequest) error {
		calls.Add(1)
		return nil
	})

	for i := 0; i < 3; i++ {
		resp, err := svc.Initialize(context.Background(), s.validInitReq())
		s.Require().NoError(err, "call %d", i)
		s.NotNil(resp)
	}
	s.Equal(int32(1), calls.Load(), "runInit must run exactly once across repeated Initialize calls")
}

// TestInitialize_Concurrent verifies many simultaneous Initialize calls
// collapse onto a single runInit and all callers observe success. This
// exercises both layers of the gate's exactly-once guarantee: the
// singleflight collapse for callers that pile up while the leader is
// still running, and the inner g.done.Load() re-check for callers that
// arrive *after* a prior singleflight batch has completed and its key
// has been deleted from the singleflight map. Without the inner check,
// such late callers would enter a fresh sf.Do entry and re-invoke
// runInit; the assertion `runInit must run exactly once` would fail
// under unfavourable scheduling.
func (s *EnclaveServiceTestSuite) TestInitialize_Concurrent() {
	const goroutines = 50

	var calls atomic.Int32
	start := make(chan struct{})
	svc := s.newUninitializedService(func(context.Context, *pb.InitializeRequest) error {
		calls.Add(1)
		// Hold the work briefly so concurrent callers genuinely race
		// against the singleflight entry rather than serialising on
		// the atomic.Bool fast-path.
		<-start
		return nil
	})

	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = svc.Initialize(context.Background(), s.validInitReq())
		}(i)
	}

	close(start)
	wg.Wait()

	for i, err := range errs {
		s.Require().NoError(err, "goroutine %d", i)
	}
	s.True(svc.gate.initialized())
	s.Equal(int32(1), calls.Load(), "runInit must run exactly once under concurrent Initialize")
}

// TestInitialize_FailureAllowsRetry verifies a failed Initialize does not
// latch the gate, and the next caller's request runs runInit again.
func (s *EnclaveServiceTestSuite) TestInitialize_FailureAllowsRetry() {
	var calls atomic.Int32
	wantErr := errors.New("simulated KMS failure")
	svc := s.newUninitializedService(func(context.Context, *pb.InitializeRequest) error {
		calls.Add(1)
		if calls.Load() == 1 {
			return wantErr
		}
		return nil
	})

	// First Initialize fails — gate stays unlatched.
	resp, err := svc.Initialize(context.Background(), s.validInitReq())
	s.Require().Error(err)
	s.Nil(resp)
	st, ok := status.FromError(err)
	s.Require().True(ok)
	s.Equal(codes.Internal, st.Code())
	s.Contains(st.Message(), "simulated KMS failure")
	s.False(svc.gate.initialized(), "gate must not latch on runInit failure")

	// Second Initialize succeeds — gate now latches.
	resp, err = svc.Initialize(context.Background(), s.validInitReq())
	s.Require().NoError(err)
	s.NotNil(resp)
	s.True(svc.gate.initialized())
	s.Equal(int32(2), calls.Load(), "runInit must run twice: once failing, once succeeding")
}

func (s *EnclaveServiceTestSuite) TestInitialize_InvalidCredentialsRegionReturnsInvalidArgument() {
	svc := s.newUninitializedService(func(_ context.Context, req *pb.InitializeRequest) error {
		_, err := awskms.BuildConfig(req.Credentials, "http://127.0.0.1:9000", false)
		return err
	})
	req := s.validInitReq()
	req.Credentials.Region = "us@east-1"

	resp, err := svc.Initialize(context.Background(), req)

	s.Require().Error(err)
	s.Nil(resp)
	s.Equal(codes.InvalidArgument, status.Code(err))
	s.False(svc.gate.initialized())
}

func (s *EnclaveServiceTestSuite) TestInitialize_RejectsUnsupportedRegionsAfterInitialization() {
	tests := map[string]func(*pb.InitializeRequest){
		"credentials region": func(req *pb.InitializeRequest) {
			req.Credentials.Region = "s3"
		},
		"ARN region": func(req *pb.InitializeRequest) {
			req.KmsKeyArns = []string{"arn:aws:kms:s3:123456789012:key/abc"}
		},
	}

	for name, mutate := range tests {
		s.Run(name, func() {
			var calls atomic.Int32
			svc := s.newUninitializedService(func(context.Context, *pb.InitializeRequest) error {
				calls.Add(1)
				return nil
			})

			resp, err := svc.Initialize(context.Background(), s.validInitReq())
			s.Require().NoError(err)
			s.NotNil(resp)

			invalidReq := s.validInitReq()
			mutate(invalidReq)
			resp, err = svc.Initialize(context.Background(), invalidReq)

			s.Require().Error(err)
			s.Nil(resp)
			s.Equal(codes.InvalidArgument, status.Code(err))
			s.Equal(int32(1), calls.Load(), "invalid retry must be rejected before the init gate")
		})
	}
}

// TestInitialize_LeaderContextDetached verifies that caller cancellation does
// not cancel the shared initialization operation. The gate timeout continues
// to bound the operation.
func (s *EnclaveServiceTestSuite) TestInitialize_LeaderContextDetached() {
	runInitStarted := make(chan struct{})
	allowReturn := make(chan struct{})
	runInitReturned := make(chan struct{})
	var runInitCtxErr atomic.Value // error observed by runInit at return
	svc := s.newUninitializedService(func(ctx context.Context, _ *pb.InitializeRequest) error {
		close(runInitStarted)
		<-allowReturn
		runInitCtxErr.Store(errOrNil(ctx.Err()))
		close(runInitReturned)
		return nil
	})

	leaderCtx, cancelLeader := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	var leaderErr error
	go func() {
		defer wg.Done()
		_, leaderErr = svc.Initialize(leaderCtx, s.validInitReq())
	}()

	<-runInitStarted   // wait until runInit is inside the closure
	cancelLeader()     // simulate leader's client disconnecting
	close(allowReturn) // let runInit finish
	<-runInitReturned

	wg.Wait()

	// runInit must have observed a non-cancelled ctx at the point of return,
	// proving the detach worked.
	s.Equal(errNil{}, runInitCtxErr.Load(),
		"runInit must see a non-cancelled context even after leader cancel")

	s.Equal(codes.Canceled, status.Code(leaderErr),
		"caller cancellation must stop only that caller's wait")
	_, retryErr := svc.Initialize(context.Background(), s.validInitReq())
	s.Require().NoError(retryErr,
		"the shared initialization must still complete for a later caller")
	s.True(svc.gate.initialized(),
		"gate must latch when runInit returns nil even if leader was cancelled")
}

func (s *EnclaveServiceTestSuite) TestInitialize_LeaderDeadlineDoesNotCancelSharedOperation() {
	runInitStarted := make(chan struct{})
	allowReturn := make(chan struct{})
	svc := s.newUninitializedService(func(ctx context.Context, _ *pb.InitializeRequest) error {
		close(runInitStarted)
		<-allowReturn
		return ctx.Err()
	})

	expiredCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	leaderDone := make(chan error, 1)
	go func() {
		_, err := svc.Initialize(expiredCtx, s.validInitReq())
		leaderDone <- err
	}()
	<-runInitStarted

	waiterDone := make(chan error, 1)
	go func() {
		_, err := svc.Initialize(context.Background(), s.validInitReq())
		waiterDone <- err
	}()

	close(allowReturn)

	s.Equal(codes.DeadlineExceeded, status.Code(<-leaderDone))
	s.Require().NoError(<-waiterDone)
	s.True(svc.gate.initialized())
}

func (s *EnclaveServiceTestSuite) TestInitialize_CanceledWaiterDoesNotBlockSharedOperation() {
	runInitStarted := make(chan struct{})
	allowReturn := make(chan struct{})
	svc := s.newUninitializedService(func(context.Context, *pb.InitializeRequest) error {
		close(runInitStarted)
		<-allowReturn
		return nil
	})

	leaderDone := make(chan error, 1)
	go func() {
		_, err := svc.Initialize(context.Background(), s.validInitReq())
		leaderDone <- err
	}()
	<-runInitStarted

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	cancelWaiter()
	waiterDone := make(chan error, 1)
	go func() {
		_, err := svc.Initialize(waiterCtx, s.validInitReq())
		waiterDone <- err
	}()

	s.Equal(codes.Canceled, status.Code(<-waiterDone))
	select {
	case err := <-leaderDone:
		s.T().Fatalf("shared initialization returned before release: %v", err)
	default:
	}

	close(allowReturn)
	s.Require().NoError(<-leaderDone)
}

// errOrNil and errNil let atomic.Value store a typed "no error" sentinel,
// since atomic.Value rejects nil interface values.
type errNil struct{}

func errOrNil(err error) any {
	if err == nil {
		return errNil{}
	}
	return err
}

func TestRunInitStatusError_KmsBranch(t *testing.T) {
	kmsErr := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "no kms"}
	got := runInitStatusError(kmsErr)
	st, ok := status.FromError(got)
	require.True(t, ok)
	require.Equal(t, codes.PermissionDenied, st.Code())
}

func TestEnclaveServiceTestSuite(t *testing.T) {
	suite.Run(t, new(EnclaveServiceTestSuite))
}
