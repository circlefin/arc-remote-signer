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
	"sync"
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newReadySigningService(t *testing.T, secretKey crypto.Key) *Service {
	t.Helper()
	return newReadyService(secretKey, false, nil)
}

func newSigningKey(t *testing.T) crypto.Key {
	t.Helper()

	secretKey, err := crypto.NewSecretKey(crypto.AlgorithmEd25519)
	require.NoError(t, err)
	return secretKey
}

func signingMetadata(kind signerv2.MessageKind, height, round uint64) *signerv2.SigningMetadata {
	return &signerv2.SigningMetadata{
		Kind:   kind,
		Height: &height,
		Round:  &round,
	}
}

func signWithMetadata(
	ctx context.Context,
	service *Service,
	message string,
	metadata *signerv2.SigningMetadata,
) error {
	_, err := service.SignMessage(ctx, &pb.SignMessageRequest{
		Message:  []byte(message),
		Metadata: metadata,
	})
	return err
}

func TestSignMessage_EnforcesWatermarkOutcomes(t *testing.T) {
	service := newReadySigningService(t, newSigningKey(t))
	ctx := context.Background()

	require.NoError(t, signWithMetadata(ctx, service, "prevote", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 10, 2,
	)))
	require.NoError(t, signWithMetadata(ctx, service, "prevote", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 10, 2,
	)), "an identical retry must be accepted")
	require.NoError(t, signWithMetadata(ctx, service, "precommit", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT, 10, 2,
	)), "precommit must use an independent namespace and advance at the same tuple")
	require.NoError(t, signWithMetadata(ctx, service, "prevote", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 10, 2,
	)), "prevote retry must still be accepted after precommit at the same tuple")

	err := signWithMetadata(ctx, service, "conflicting-precommit", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT, 10, 2,
	))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	err = signWithMetadata(ctx, service, "conflicting-prevote", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 10, 2,
	))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	err = signWithMetadata(ctx, service, "older-prevote", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 10, 1,
	))
	require.Equal(t, codes.OutOfRange, status.Code(err))

	err = signWithMetadata(ctx, service, "older-precommit", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT, 9, 0,
	))
	require.Equal(t, codes.OutOfRange, status.Code(err))

	require.NoError(t, signWithMetadata(ctx, service, "proposal", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PROPOSAL, 10, 2,
	)), "proposal must use an independent namespace")
	require.NoError(t, signWithMetadata(ctx, service, "proposal-parts", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PROPOSAL_PARTS, 10, 2,
	)), "proposal parts must use an independent namespace")
}

func TestSignMessage_EnforcesCrossKindPrevoteBoundary(t *testing.T) {
	service := newReadySigningService(t, newSigningKey(t))
	ctx := context.Background()

	require.NoError(t, signWithMetadata(ctx, service, "precommit", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT, 10, 2,
	)))
	require.NoError(t, signWithMetadata(ctx, service, "prevote-at-boundary", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 10, 2,
	)), "an empty in-memory prevote watermark may sign at the precommit boundary after restart")
	require.NoError(t, signWithMetadata(ctx, service, "prevote-at-boundary", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 10, 2,
	)), "an identical prevote retry at the boundary must remain accepted")

	service = newReadySigningService(t, newSigningKey(t))
	require.NoError(t, signWithMetadata(ctx, service, "precommit", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT, 10, 2,
	)))
	err := signWithMetadata(ctx, service, "prevote-below-boundary", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 10, 1,
	))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.ErrorContains(t, err, "watermark violation")
}

func TestSignMessage_EnforcesProposalStepOrdering(t *testing.T) {
	service := newReadySigningService(t, newSigningKey(t))
	ctx := context.Background()

	require.NoError(t, signWithMetadata(ctx, service, "precommit", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT, 10, 2,
	)))
	err := signWithMetadata(ctx, service, "older-proposal", signingMetadata(
		signerv2.MessageKind_MESSAGE_KIND_PROPOSAL, 10, 1,
	))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.ErrorContains(t, err, "watermark violation")
}

func TestSignMessage_RejectsInvalidWatermarkMetadata(t *testing.T) {
	service := newReadySigningService(t, newSigningKey(t))
	height := uint64(10)
	round := uint64(2)
	tests := map[string]*signerv2.SigningMetadata{
		"unspecified kind": {
			Height: &height,
			Round:  &round,
		},
		"unknown kind": {
			Kind:   signerv2.MessageKind(99),
			Height: &height,
			Round:  &round,
		},
		"missing height": {
			Kind:  signerv2.MessageKind_MESSAGE_KIND_PREVOTE,
			Round: &round,
		},
		"missing round": {
			Kind:   signerv2.MessageKind_MESSAGE_KIND_PREVOTE,
			Height: &height,
		},
		"zero height": signingMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 0, 2),
		"validator proof with tuple": signingMetadata(
			signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF, 10, 2,
		),
		"telemetry with tuple": signingMetadata(
			signerv2.MessageKind_MESSAGE_KIND_TELEMETRY, 10, 2,
		),
	}

	for name, metadata := range tests {
		t.Run(name, func(t *testing.T) {
			err := signWithMetadata(context.Background(), service, name, metadata)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestSignMessage_BypassesWatermarkForLegacyAndValidatorProof(t *testing.T) {
	service := newReadySigningService(t, newSigningKey(t))
	ctx := context.Background()

	require.NoError(t, signWithMetadata(ctx, service, "legacy-a", nil))
	require.NoError(t, signWithMetadata(ctx, service, "legacy-b", nil))

	validatorProof := &signerv2.SigningMetadata{Kind: signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF}
	require.NoError(t, signWithMetadata(ctx, service, "proof-a", validatorProof))
	require.NoError(t, signWithMetadata(ctx, service, "proof-b", validatorProof))
}

func TestSignMessage_Delegation(t *testing.T) {
	secretKey := newSigningKey(t)
	service := newReadySigningService(t, secretKey)
	message := make([]byte, 130)
	copy(message, []byte("arc/auth/v1\x00\x09arc-boost"))
	metadata := &signerv2.SigningMetadata{Kind: signerv2.MessageKind_MESSAGE_KIND_DELEGATION}
	response, err := service.SignMessage(context.Background(), &pb.SignMessageRequest{Message: message, Metadata: metadata})
	require.NoError(t, err)
	require.Empty(t, service.watermarks)
	publicKey, err := secretKey.PublicKey()
	require.NoError(t, err)
	valid, err := crypto.VerifySignedMessage(crypto.AlgorithmEd25519, response.Signature, message, publicKey)
	require.NoError(t, err)
	require.True(t, valid)
	message[len(message)-1] ^= 1
	valid, err = crypto.VerifySignedMessage(crypto.AlgorithmEd25519, response.Signature, message, publicKey)
	require.NoError(t, err)
	require.False(t, valid)
}

func TestSignMessage_RejectsInvalidDelegationBeforeKeyRecovery(t *testing.T) {
	tests := map[string][]byte{
		"short message": []byte("arc/auth/v1\x00"),
		"wrong domain":  append([]byte("arc/auth/v1\x00\x09arc-boots"), make([]byte, 108)...),
	}
	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			service := New(false, nil, nil, "")
			response, err := service.SignMessage(context.Background(), &pb.SignMessageRequest{
				Message: message, Metadata: &signerv2.SigningMetadata{Kind: signerv2.MessageKind_MESSAGE_KIND_DELEGATION},
			})
			require.Nil(t, response)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestSignMessage_BypassesWatermarkForTelemetry(t *testing.T) {
	secretKey := newSigningKey(t)
	service := newReadySigningService(t, secretKey)
	message := append([]byte("arc/telemetry/v1\x00"), make([]byte, 32)...)
	metadata := &signerv2.SigningMetadata{Kind: signerv2.MessageKind_MESSAGE_KIND_TELEMETRY}

	response, err := service.SignMessage(context.Background(), &pb.SignMessageRequest{
		Message:  message,
		Metadata: metadata,
	})

	require.NoError(t, err)
	require.Empty(t, service.watermarks)
	publicKey, err := secretKey.PublicKey()
	require.NoError(t, err)
	valid, err := crypto.VerifySignedMessage(crypto.AlgorithmEd25519, response.Signature, message, publicKey)
	require.NoError(t, err)
	require.True(t, valid)
	valid, err = crypto.VerifySignedMessage(
		crypto.AlgorithmEd25519,
		response.Signature,
		append(message, byte(0)),
		publicKey,
	)
	require.NoError(t, err)
	require.False(t, valid)
}

func TestSignMessage_RejectsInvalidTelemetryMessages(t *testing.T) {
	tests := map[string][]byte{
		"short digest": append([]byte("arc/telemetry/v1\x00"), make([]byte, 31)...),
		"long digest":  append([]byte("arc/telemetry/v1\x00"), make([]byte, 33)...),
		"wrong domain": append([]byte("arc/telemetry/v2\x00"), make([]byte, 32)...),
		"missing null": append([]byte("arc/telemetry/v1x"), make([]byte, 32)...),
	}

	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			service := newReadySigningService(t, newSigningKey(t))

			response, err := service.SignMessage(context.Background(), &pb.SignMessageRequest{
				Message: message,
				Metadata: &signerv2.SigningMetadata{
					Kind: signerv2.MessageKind_MESSAGE_KIND_TELEMETRY,
				},
			})

			require.Nil(t, response)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestSignMessage_RejectsInvalidTelemetryBeforeKeyRecovery(t *testing.T) {
	service := New(false, nil, nil, "")
	response, err := service.SignMessage(context.Background(), &pb.SignMessageRequest{
		Message: []byte("invalid-telemetry"),
		Metadata: &signerv2.SigningMetadata{
			Kind: signerv2.MessageKind_MESSAGE_KIND_TELEMETRY,
		},
	})

	require.Nil(t, response)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestSignMessage_NewServiceResetsWatermark(t *testing.T) {
	secretKey := newSigningKey(t)
	service := newReadySigningService(t, secretKey)
	metadata := signingMetadata(signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT, 10, 2)

	require.NoError(t, signWithMetadata(context.Background(), service, "before-restart", metadata))

	restarted := newReadySigningService(t, secretKey)
	require.NoError(t, signWithMetadata(context.Background(), restarted, "after-restart", metadata))
}

func TestSignMessage_ConcurrentConflictAllowsOneSignature(t *testing.T) {
	service := newReadySigningService(t, newSigningKey(t))
	metadata := signingMetadata(signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT, 10, 2)
	messages := []string{"message-a", "message-b"}
	start := make(chan struct{})
	errors := make(chan error, len(messages))
	var ready sync.WaitGroup
	ready.Add(len(messages))

	for _, message := range messages {
		go func() {
			ready.Done()
			<-start
			errors <- signWithMetadata(context.Background(), service, message, metadata)
		}()
	}
	ready.Wait()
	close(start)

	var signed, rejected int
	for range messages {
		err := <-errors
		if err == nil {
			signed++
			continue
		}
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		rejected++
	}
	require.Equal(t, 1, signed)
	require.Equal(t, 1, rejected)
}
