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

package v2

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/circlefin/arc-remote-signer/internal/common/replica"
	"github.com/circlefin/arc-remote-signer/internal/common/watermark"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func testMetadata(kind signerv2.MessageKind, height uint64) *signerv2.SigningMetadata {
	return &signerv2.SigningMetadata{
		Kind:   kind,
		Height: proto.Uint64(height),
		Round:  proto.Uint64(2),
	}
}

const testReplicaName = "validator-01-a"

type doneObservedContext struct {
	context.Context
	observed chan struct{}
	notified atomic.Bool
}

func (c *doneObservedContext) Done() <-chan struct{} {
	if c.notified.CompareAndSwap(false, true) {
		close(c.observed)
	}
	return c.Context.Done()
}

func observeDone(parent context.Context) (context.Context, context.CancelFunc, <-chan struct{}) {
	ctx, cancel := context.WithCancel(parent)
	observed := make(chan struct{})
	return &doneObservedContext{Context: ctx, observed: observed}, cancel, observed
}

func newTestService(t *testing.T) (*Service, *MockBaseSigner, *watermark.MockOwnedAdvancer) {
	t.Helper()
	ctrl := gomock.NewController(t)
	base := NewMockBaseSigner(ctrl)
	repository := watermark.NewMockOwnedAdvancer(ctrl)
	service, err := New(base, repository)
	require.NoError(t, err)
	return service, base, repository
}

func TestNew(t *testing.T) {
	ctrl := gomock.NewController(t)
	base := NewMockBaseSigner(ctrl)
	repository := watermark.NewMockOwnedAdvancer(ctrl)

	tests := map[string]struct {
		base       BaseSigner
		repository watermark.OwnedAdvancer
		wantError  string
	}{
		"valid dependencies": {
			base:       base,
			repository: repository,
		},
		"missing base signer": {
			repository: repository,
			wantError:  "base signer service is required",
		},
		"missing repository": {
			base:      base,
			wantError: "watermark repository is required",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			service, err := New(tt.base, tt.repository)

			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
				require.Nil(t, service)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, service)
		})
	}
}

func TestService_PublicKey(t *testing.T) {
	tests := map[string]struct {
		baseError error
		wantCode  codes.Code
	}{
		"converts base response": {},
		"returns base error": {
			baseError: status.Error(codes.Unavailable, "base unavailable"),
			wantCode:  codes.Unavailable,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			service, base, _ := newTestService(t)
			base.EXPECT().
				PublicKey(gomock.Any(), &pb.PublicKeyRequest{}).
				Return(&pb.PublicKeyResponse{
					PublicKey:           []byte("public-key"),
					AttestationDocument: []byte("attestation"),
				}, tt.baseError)

			response, err := service.PublicKey(context.Background(), &signerv2.PublicKeyRequest{})

			if tt.baseError != nil {
				require.Nil(t, response)
				require.Equal(t, tt.wantCode, status.Code(err))
				return
			}
			require.NoError(t, err)
			require.Equal(t, []byte("public-key"), response.PublicKey)
			require.Equal(t, []byte("attestation"), response.AttestationDocument)
		})
	}
}

func TestService_SignRejectsInvalidRequests(t *testing.T) {
	tests := map[string]*signerv2.SignRequest{
		"nil request": nil,
		"empty message": {
			Metadata: testMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 1),
		},
		"missing metadata": {
			Message: []byte("message"),
		},
		"unspecified kind": {
			Message:  []byte("message"),
			Metadata: testMetadata(signerv2.MessageKind_MESSAGE_KIND_UNSPECIFIED, 1),
		},
		"zero height": {
			Message:  []byte("message"),
			Metadata: testMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 0),
		},
		"validator proof contains a consensus position": {
			Message:  []byte("message"),
			Metadata: testMetadata(signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF, 1),
		},
	}

	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			service, _, _ := newTestService(t)

			response, err := service.Sign(context.Background(), request)

			require.Nil(t, response)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
			require.Equal(t, "invalid watermark candidate", status.Convert(err).Message())
		})
	}
}

func TestService_SignAcceptsConfirmedWatermarkOutcomes(t *testing.T) {
	tests := map[string]watermark.Outcome{
		"advanced":  watermark.OutcomeAdvanced,
		"unchanged": watermark.OutcomeUnchanged,
	}

	for name, outcome := range tests {
		t.Run(name, func(t *testing.T) {
			service, base, repository := newTestService(t)
			message := []byte("message")
			metadata := testMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 10)
			namespace, candidate, required, err := watermark.CandidateFromSigningMetadata(metadata, message)
			require.NoError(t, err)
			require.True(t, required)

			expectedReplica, err := replica.NewID(testReplicaName)
			require.NoError(t, err)
			gomock.InOrder(
				repository.EXPECT().
					CompareAndAdvance(gomock.Any(), namespace, candidate, expectedReplica).
					Return(outcome, nil),
				base.EXPECT().
					SignEnclave(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, request *pb.SignMessageRequest) (*pb.SignMessageResponse, error) {
						require.Same(t, metadata, request.Metadata)
						require.Equal(t, message, request.Message)
						require.True(t, &message[0] == &request.Message[0])
						return &pb.SignMessageResponse{Signature: []byte("signature")}, nil
					}),
			)

			response, err := service.Sign(context.Background(), &signerv2.SignRequest{
				Message:     message,
				Metadata:    metadata,
				ReplicaName: testReplicaName,
			})

			require.NoError(t, err)
			require.Equal(t, []byte("signature"), response.Signature)
		})
	}
}

func TestService_SignValidatorProofSkipsRepository(t *testing.T) {
	service, base, _ := newTestService(t)
	message := []byte("validator-proof")
	metadata := &signerv2.SigningMetadata{
		Kind: signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF,
	}
	base.EXPECT().
		SignEnclave(gomock.Any(), &pb.SignMessageRequest{
			Message:  message,
			Metadata: metadata,
		}).
		Return(&pb.SignMessageResponse{Signature: []byte("signature")}, nil)

	response, err := service.Sign(context.Background(), &signerv2.SignRequest{
		Message:     message,
		Metadata:    metadata,
		ReplicaName: testReplicaName,
	})

	require.NoError(t, err)
	require.Equal(t, []byte("signature"), response.Signature)
}

func TestService_SignDelegation(t *testing.T) {
	message := make([]byte, 130)
	copy(message, []byte("arc/auth/v1\x00\x09arc-boost"))
	tests := map[string]struct {
		message []byte
		wantErr bool
	}{
		"valid delegation": {message: message},
		"short delegation": {message: message[:129], wantErr: true},
		"wrong domain":     {message: append([]byte("arc/auth/v1\x00\x09arc-boots"), make([]byte, 108)...), wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			service, base, _ := newTestService(t)
			metadata := &signerv2.SigningMetadata{Kind: signerv2.MessageKind_MESSAGE_KIND_DELEGATION}
			if !tt.wantErr {
				base.EXPECT().SignEnclave(gomock.Any(), &pb.SignMessageRequest{Message: tt.message, Metadata: metadata}).
					Return(&pb.SignMessageResponse{Signature: []byte("signature")}, nil)
			}
			response, err := service.Sign(context.Background(), &signerv2.SignRequest{
				Message: tt.message, Metadata: metadata, ReplicaName: testReplicaName,
			})
			if tt.wantErr {
				require.Nil(t, response)
				require.Equal(t, codes.InvalidArgument, status.Code(err))
				return
			}
			require.NoError(t, err)
			require.Equal(t, []byte("signature"), response.Signature)
		})
	}
}

func TestService_SignTelemetrySkipsRepository(t *testing.T) {
	service, base, _ := newTestService(t)
	message := append([]byte("arc/telemetry/v1\x00"), make([]byte, 32)...)
	metadata := &signerv2.SigningMetadata{Kind: signerv2.MessageKind_MESSAGE_KIND_TELEMETRY}
	base.EXPECT().
		SignEnclave(gomock.Any(), &pb.SignMessageRequest{
			Message:  message,
			Metadata: metadata,
		}).
		Return(&pb.SignMessageResponse{Signature: []byte("signature")}, nil)

	response, err := service.Sign(context.Background(), &signerv2.SignRequest{
		Message:     message,
		Metadata:    metadata,
		ReplicaName: testReplicaName,
	})

	require.NoError(t, err)
	require.Equal(t, []byte("signature"), response.Signature)
}

func TestService_SignRejectsInvalidTelemetryMessages(t *testing.T) {
	tests := map[string][]byte{
		"short digest": append([]byte("arc/telemetry/v1\x00"), make([]byte, 31)...),
		"long digest":  append([]byte("arc/telemetry/v1\x00"), make([]byte, 33)...),
		"wrong domain": append([]byte("arc/telemetry/v2\x00"), make([]byte, 32)...),
		"missing null": append([]byte("arc/telemetry/v1x"), make([]byte, 32)...),
	}

	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			service, _, _ := newTestService(t)

			response, err := service.Sign(context.Background(), &signerv2.SignRequest{
				Message:     message,
				ReplicaName: testReplicaName,
				Metadata: &signerv2.SigningMetadata{
					Kind: signerv2.MessageKind_MESSAGE_KIND_TELEMETRY,
				},
			})

			require.Nil(t, response)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
			require.Equal(t, errInvalidCandidate, status.Convert(err).Message())
		})
	}
}

func TestService_SignMapsRepositoryErrors(t *testing.T) {
	tests := map[string]struct {
		repositoryError error
		wantCode        codes.Code
		wantMessage     string
	}{
		"invalid candidate": {
			repositoryError: fmt.Errorf("wrapped: %w", watermark.ErrInvalidCandidate),
			wantCode:        codes.InvalidArgument,
			wantMessage:     "invalid watermark candidate",
		},
		"violation": {
			repositoryError: watermark.ErrWatermarkViolation,
			wantCode:        codes.FailedPrecondition,
			wantMessage:     "watermark violation",
		},
		"stale": {
			repositoryError: watermark.ErrWatermarkStale,
			wantCode:        codes.OutOfRange,
			wantMessage:     "watermark stale",
		},
		"owner conflict": {
			repositoryError: watermark.ErrWatermarkOwnerConflict,
			wantCode:        codes.Aborted,
			wantMessage:     "other node signed",
		},
		"indeterminate": {
			repositoryError: watermark.ErrWatermarkIndeterminate,
			wantCode:        codes.Internal,
			wantMessage:     "watermark result indeterminate; retry the exact same request",
		},
		"corrupt": {
			repositoryError: watermark.ErrWatermarkCorrupt,
			wantCode:        codes.Internal,
			wantMessage:     "watermark state corrupt; operator action required",
		},
		"corrupt with invalid stored candidate": {
			repositoryError: fmt.Errorf(
				"%w: stored state: %w",
				watermark.ErrWatermarkCorrupt,
				watermark.ErrInvalidCandidate,
			),
			wantCode:    codes.Internal,
			wantMessage: "watermark state corrupt; operator action required",
		},
		"unknown repository error": {
			repositoryError: errors.New("DynamoDB unavailable"),
			wantCode:        codes.Internal,
			wantMessage:     "watermark repository failure",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			service, _, repository := newTestService(t)
			message := []byte("message")
			metadata := testMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 10)
			namespace, candidate, required, err := watermark.CandidateFromSigningMetadata(metadata, message)
			require.NoError(t, err)
			require.True(t, required)
			expectedReplica, err := replica.NewID(testReplicaName)
			require.NoError(t, err)
			repository.EXPECT().
				CompareAndAdvance(gomock.Any(), namespace, candidate, expectedReplica).
				Return(watermark.Outcome(0), tt.repositoryError)

			response, err := service.Sign(context.Background(), &signerv2.SignRequest{
				Message:     message,
				Metadata:    metadata,
				ReplicaName: testReplicaName,
			})

			require.Nil(t, response)
			require.Equal(t, tt.wantCode, status.Code(err))
			require.Equal(t, tt.wantMessage, status.Convert(err).Message())
		})
	}
}

func TestService_SignRejectsUnknownRepositoryOutcome(t *testing.T) {
	service, _, repository := newTestService(t)
	repository.EXPECT().
		CompareAndAdvance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(watermark.Outcome(99), nil)

	response, err := service.Sign(context.Background(), &signerv2.SignRequest{
		Message:     []byte("message"),
		Metadata:    testMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 10),
		ReplicaName: testReplicaName,
	})

	require.Nil(t, response)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Equal(t, "watermark repository failure", status.Convert(err).Message())
}

func TestService_SignMapsEnclaveErrorsWithoutFallback(t *testing.T) {
	tests := map[string]struct {
		enclaveError error
		wantCode     codes.Code
		wantMessage  string
	}{
		"watermark violation": {
			enclaveError: status.Error(codes.FailedPrecondition, "watermark violation: tuple=(10,2,0)"),
			wantCode:     codes.FailedPrecondition,
			wantMessage:  "watermark violation",
		},
		"stale watermark": {
			enclaveError: status.Error(codes.OutOfRange, "watermark stale: current=(11,0,0)"),
			wantCode:     codes.OutOfRange,
			wantMessage:  "watermark stale",
		},
		"unrelated enclave error": {
			enclaveError: status.Error(codes.PermissionDenied, "sensitive enclave details"),
			wantCode:     codes.Internal,
			wantMessage:  "failed to sign message",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			service, base, repository := newTestService(t)
			gomock.InOrder(
				repository.EXPECT().
					CompareAndAdvance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(watermark.OutcomeAdvanced, nil),
				base.EXPECT().
					SignEnclave(gomock.Any(), gomock.Any()).
					Return(nil, tt.enclaveError),
			)

			response, err := service.Sign(context.Background(), &signerv2.SignRequest{
				Message:     []byte("message"),
				Metadata:    testMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 10),
				ReplicaName: testReplicaName,
			})

			require.Nil(t, response)
			require.Equal(t, tt.wantCode, status.Code(err))
			require.Equal(t, tt.wantMessage, status.Convert(err).Message())
		})
	}
}

func TestService_SignCanceledWaiterDoesNotReachRepository(t *testing.T) {
	tests := map[string]struct {
		wantCode codes.Code
	}{
		"canceled":          {wantCode: codes.Canceled},
		"deadline exceeded": {wantCode: codes.DeadlineExceeded},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			service, base, repository := newTestService(t)
			firstEnclaveEntered := make(chan struct{})
			releaseFirstEnclave := make(chan struct{})
			t.Cleanup(func() {
				select {
				case <-releaseFirstEnclave:
				default:
					close(releaseFirstEnclave)
				}
			})

			repository.EXPECT().
				CompareAndAdvance(gomock.Any(), watermark.NamespacePrevotes, gomock.Any(), gomock.Any()).
				Return(watermark.OutcomeAdvanced, nil)
			base.EXPECT().
				SignEnclave(gomock.Any(), gomock.Any()).
				DoAndReturn(func(context.Context, *pb.SignMessageRequest) (*pb.SignMessageResponse, error) {
					close(firstEnclaveEntered)
					<-releaseFirstEnclave
					return &pb.SignMessageResponse{Signature: []byte("signature")}, nil
				})

			firstResult := make(chan error, 1)
			go func() {
				_, err := service.Sign(context.Background(), &signerv2.SignRequest{
					Message:     []byte("first"),
					Metadata:    testMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 1),
					ReplicaName: testReplicaName,
				})
				firstResult <- err
			}()
			require.Eventually(t, func() bool {
				select {
				case <-firstEnclaveEntered:
					return true
				default:
					return false
				}
			}, time.Second, time.Millisecond)

			parent := context.Background()
			if tt.wantCode == codes.DeadlineExceeded {
				var stop context.CancelFunc
				parent, stop = context.WithTimeout(parent, 200*time.Millisecond)
				defer stop()
			}
			ctx, cancel, waiting := observeDone(parent)
			secondResult := make(chan error, 1)
			go func() {
				_, err := service.Sign(ctx, &signerv2.SignRequest{
					Message:     []byte("second"),
					Metadata:    testMetadata(signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT, 2),
					ReplicaName: testReplicaName,
				})
				secondResult <- err
			}()
			defer cancel()
			select {
			case <-waiting:
			case <-time.After(time.Second):
				t.Fatal("request did not start waiting with its context")
			}
			if tt.wantCode == codes.Canceled {
				cancel()
			}
			select {
			case err := <-secondResult:
				require.Equal(t, tt.wantCode, status.Code(err))
			case <-time.After(time.Second):
				t.Fatal("canceled request did not stop waiting")
			}

			close(releaseFirstEnclave)
			require.NoError(t, <-firstResult)
		})
	}
}

func TestService_SignSerializesWatermarkedKindsThroughEnclave(t *testing.T) {
	tests := map[string]struct {
		namespace watermark.Namespace
		kind      signerv2.MessageKind
	}{
		"prevotes":       {namespace: watermark.NamespacePrevotes, kind: signerv2.MessageKind_MESSAGE_KIND_PREVOTE},
		"precommits":     {namespace: watermark.NamespacePrecommits, kind: signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT},
		"proposals":      {namespace: watermark.NamespaceProposals, kind: signerv2.MessageKind_MESSAGE_KIND_PROPOSAL},
		"proposal parts": {namespace: watermark.NamespaceProposalParts, kind: signerv2.MessageKind_MESSAGE_KIND_PROPOSAL_PARTS},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			service, base, repository := newTestService(t)
			prevoteEnclaveEntered := make(chan struct{})
			releasePrevoteEnclave := make(chan struct{})
			t.Cleanup(func() {
				select {
				case <-releasePrevoteEnclave:
				default:
					close(releasePrevoteEnclave)
				}
			})
			precommitRepositoryEntered := make(chan struct{})

			repository.EXPECT().
				CompareAndAdvance(gomock.Any(), watermark.NamespacePrevotes, gomock.Any(), gomock.Any()).
				Return(watermark.OutcomeAdvanced, nil)
			repository.EXPECT().
				CompareAndAdvance(gomock.Any(), tt.namespace, gomock.Any(), gomock.Any()).
				DoAndReturn(func(context.Context, watermark.Namespace, watermark.Watermark, replica.ID) (watermark.Outcome, error) {
					close(precommitRepositoryEntered)
					return watermark.OutcomeAdvanced, nil
				})
			base.EXPECT().
				SignEnclave(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, request *pb.SignMessageRequest) (*pb.SignMessageResponse, error) {
					if string(request.Message) == "prevote" {
						close(prevoteEnclaveEntered)
						<-releasePrevoteEnclave
					}
					return &pb.SignMessageResponse{Signature: []byte("signature")}, nil
				}).
				Times(2)

			sign := func(ctx context.Context, kind signerv2.MessageKind, message string) <-chan error {
				result := make(chan error, 1)
				go func() {
					_, err := service.Sign(ctx, &signerv2.SignRequest{
						Message:     []byte(message),
						Metadata:    testMetadata(kind, 1),
						ReplicaName: testReplicaName,
					})
					result <- err
				}()
				return result
			}

			prevoteResult := sign(context.Background(), signerv2.MessageKind_MESSAGE_KIND_PREVOTE, "prevote")
			require.Eventually(t, func() bool {
				select {
				case <-prevoteEnclaveEntered:
					return true
				default:
					return false
				}
			}, time.Second, time.Millisecond)

			ctx, cancel, waiting := observeDone(context.Background())
			defer cancel()
			precommitResult := sign(ctx, tt.kind, "next")
			select {
			case <-waiting:
			case <-precommitRepositoryEntered:
				t.Fatal("second request reached repository before the first enclave response")
			case <-time.After(time.Second):
				t.Fatal("second request did not start waiting")
			}
			require.Never(t, func() bool {
				select {
				case <-precommitRepositoryEntered:
					return true
				default:
					return false
				}
			}, 100*time.Millisecond, time.Millisecond)
			close(releasePrevoteEnclave)
			require.NoError(t, <-prevoteResult)
			require.NoError(t, <-precommitResult)
		})
	}
}

func TestService_SignReleasesPermitAfterFailure(t *testing.T) {
	tests := map[string]struct {
		repositoryError error
		enclaveError    error
	}{
		"repository": {repositoryError: errors.New("repository unavailable")},
		"enclave":    {enclaveError: errors.New("enclave unavailable")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			service, base, repository := newTestService(t)
			firstRepository := repository.EXPECT().CompareAndAdvance(gomock.Any(), watermark.NamespacePrevotes, gomock.Any(), gomock.Any())
			if tt.repositoryError != nil {
				firstRepository.Return(watermark.Outcome(0), tt.repositoryError)
			} else {
				firstRepository.Return(watermark.OutcomeAdvanced, nil)
				base.EXPECT().SignEnclave(gomock.Any(), gomock.Any()).Return(nil, tt.enclaveError)
			}
			request := &signerv2.SignRequest{Message: []byte("message"), Metadata: testMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 1), ReplicaName: testReplicaName}
			_, err := service.Sign(context.Background(), request)
			require.Equal(t, codes.Internal, status.Code(err))

			repository.EXPECT().CompareAndAdvance(gomock.Any(), watermark.NamespacePrevotes, gomock.Any(), gomock.Any()).Return(watermark.OutcomeAdvanced, nil)
			base.EXPECT().SignEnclave(gomock.Any(), gomock.Any()).Return(&pb.SignMessageResponse{Signature: []byte("signature")}, nil)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			response, err := service.Sign(ctx, request)
			require.NoError(t, err)
			require.Equal(t, []byte("signature"), response.Signature)
		})
	}
}

func TestService_SignTuplelessRequestsBypassBusyPermit(t *testing.T) {
	service, base, repository := newTestService(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	repository.EXPECT().CompareAndAdvance(gomock.Any(), watermark.NamespacePrevotes, gomock.Any(), gomock.Any()).Return(watermark.OutcomeAdvanced, nil)
	base.EXPECT().SignEnclave(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, req *pb.SignMessageRequest) (*pb.SignMessageResponse, error) {
		if req.Metadata.Kind == signerv2.MessageKind_MESSAGE_KIND_PREVOTE {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return &pb.SignMessageResponse{Signature: []byte("signature")}, nil
	}).Times(4)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	defer func() {
		close(release)
		select {
		case err := <-result:
			if err != nil {
				t.Errorf("watermarked request failed: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("watermarked request did not finish after release")
		}
	}()
	go func() {
		_, err := service.Sign(ctx, &signerv2.SignRequest{Message: []byte("prevote"), Metadata: testMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 1), ReplicaName: testReplicaName})
		result <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("watermarked request did not enter enclave")
	}
	for _, kind := range []signerv2.MessageKind{signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF, signerv2.MessageKind_MESSAGE_KIND_TELEMETRY, signerv2.MessageKind_MESSAGE_KIND_DELEGATION} {
		message := []byte("proof")
		if kind == signerv2.MessageKind_MESSAGE_KIND_TELEMETRY {
			message = append([]byte("arc/telemetry/v1\x00"), make([]byte, 32)...)
		}
		if kind == signerv2.MessageKind_MESSAGE_KIND_DELEGATION {
			message = make([]byte, 130)
			copy(message, []byte("arc/auth/v1\x00\x09arc-boost"))
		}
		response, err := service.Sign(ctx, &signerv2.SignRequest{Message: message, Metadata: &signerv2.SigningMetadata{Kind: kind}, ReplicaName: testReplicaName})
		require.NoError(t, err)
		require.Equal(t, []byte("signature"), response.Signature)
	}
	select {
	case err := <-result:
		t.Fatalf("watermarked request returned before release: %v", err)
	default:
	}
}

func TestWatermarkStatusError_InternalModeIsNotClientInput(t *testing.T) {
	_, _, err := watermark.AdvanceState(nil, watermark.NamespacePrevotes, watermark.Watermark{
		Tuple: watermark.Tuple{Height: 1}, MessageHash: watermark.HashMessage([]byte("message")),
	}, watermark.CrossKindMode(0))
	require.Error(t, err)
	mapped := watermarkStatusError(context.Background(), err)
	require.Equal(t, codes.Internal, status.Code(mapped))
	require.Equal(t, errWatermarkRepository, status.Convert(mapped).Message())
}
