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

package proto

import (
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestSignRequestValidation_Delegation(t *testing.T) {
	require.Equal(t, int32(7), int32(signerv2.MessageKind_MESSAGE_KIND_DELEGATION))
	validator, err := protovalidate.New()
	require.NoError(t, err)
	tests := map[string]struct {
		height  *uint64
		round   *uint64
		wantErr bool
	}{
		"without tuple":   {},
		"with height":     {height: proto.Uint64(1), wantErr: true},
		"with round zero": {round: proto.Uint64(0), wantErr: true},
		"with tuple":      {height: proto.Uint64(1), round: proto.Uint64(0), wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validator.Validate(&signerv2.SignRequest{
				Message: []byte("message"), ReplicaName: "primary",
				Metadata: &signerv2.SigningMetadata{Kind: signerv2.MessageKind_MESSAGE_KIND_DELEGATION, Height: tt.height, Round: tt.round},
			})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestLeaseRequestValidation(t *testing.T) {
	validator, err := protovalidate.New()
	require.NoError(t, err)

	tests := map[string]struct {
		replicaName   string
		sessionID     []byte
		decidedHeight uint64
		wantValid     bool
	}{
		"new node at height zero":  {replicaName: "primary", sessionID: []byte{1}, wantValid: true},
		"node with decided height": {replicaName: "primary", sessionID: []byte{1}, decidedHeight: 42, wantValid: true},
		"URI replica name":         {replicaName: "spiffe://example.org/validator/primary", sessionID: []byte{1}, wantValid: true},
		"maximum replica name":     {replicaName: strings.Repeat("a", 255), sessionID: []byte{1}, wantValid: true},
		"maximum session":          {replicaName: "primary", sessionID: make([]byte, 64), wantValid: true},
		"missing replica name":     {sessionID: []byte{1}},
		"replica name with spaces": {replicaName: "primary node", sessionID: []byte{1}},
		"non-ASCII replica name":   {replicaName: "主節點", sessionID: []byte{1}},
		"replica name too long":    {replicaName: strings.Repeat("a", 256), sessionID: []byte{1}},
		"missing session":          {replicaName: "primary"},
		"session too long":         {replicaName: "primary", sessionID: make([]byte, 65)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			requests := []proto.Message{
				&signerv2.AcquireOrRenewLeaseRequest{
					ReplicaName:   tt.replicaName,
					SessionId:     tt.sessionID,
					DecidedHeight: tt.decidedHeight,
				},
				&signerv2.ReleaseLeaseRequest{ReplicaName: tt.replicaName, SessionId: tt.sessionID},
			}
			for _, request := range requests {
				err := validator.Validate(request)
				if tt.wantValid {
					require.NoError(t, err, "%T", request)
				} else {
					require.Error(t, err, "%T", request)
				}
			}
		})
	}
}

func watermarkedMetadata(kind signerv2.MessageKind, height, round uint64) *signerv2.SigningMetadata {
	return &signerv2.SigningMetadata{
		Kind:   kind,
		Height: proto.Uint64(height),
		Round:  proto.Uint64(round),
	}
}

func TestSignRequestValidation_AcceptsSupportedKinds(t *testing.T) {
	validator, err := protovalidate.New()
	require.NoError(t, err)

	tests := map[string]*signerv2.SignRequest{
		"prevote": {
			Message:     []byte("prevote"),
			Metadata:    watermarkedMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 1, 0),
			ReplicaName: "validator-01-a",
		},
		"precommit": {
			Message:     []byte("precommit"),
			Metadata:    watermarkedMetadata(signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT, 1, 0),
			ReplicaName: "spiffe://circle/validators/validator-01/replicas/a",
		},
		"proposal": {
			Message:     []byte("proposal"),
			Metadata:    watermarkedMetadata(signerv2.MessageKind_MESSAGE_KIND_PROPOSAL, 1, 0),
			ReplicaName: "validator-01-a",
		},
		"proposal parts": {
			Message:     []byte("proposal-parts"),
			Metadata:    watermarkedMetadata(signerv2.MessageKind_MESSAGE_KIND_PROPOSAL_PARTS, 1, 0),
			ReplicaName: "validator-01-a",
		},
		"validator proof": {
			Message:     []byte("validator-proof"),
			ReplicaName: "validator-01-a",
			Metadata: &signerv2.SigningMetadata{
				Kind: signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF,
			},
		},
		"telemetry": {
			Message:     append([]byte("arc/telemetry/v1\x00"), make([]byte, 32)...),
			ReplicaName: "validator-01-a",
			Metadata: &signerv2.SigningMetadata{
				Kind: signerv2.MessageKind_MESSAGE_KIND_TELEMETRY,
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, validator.Validate(tt))
		})
	}
}

func TestSignRequestValidation_SessionID(t *testing.T) {
	validator, err := protovalidate.New()
	require.NoError(t, err)

	tests := map[string]struct {
		sessionID []byte
		wantValid bool
	}{
		"phase one without session": {wantValid: true},
		"process session":           {sessionID: []byte{1}, wantValid: true},
		"maximum session":           {sessionID: make([]byte, 64), wantValid: true},
		"session too long":          {sessionID: make([]byte, 65)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validator.Validate(&signerv2.SignRequest{
				Message:     []byte("message"),
				Metadata:    watermarkedMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 1, 0),
				ReplicaName: "primary",
				SessionId:   tt.sessionID,
			})
			if tt.wantValid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestSignRequestValidation_RejectsInvalidReplicaName(t *testing.T) {
	validator, err := protovalidate.New()
	require.NoError(t, err)

	tests := map[string]string{
		"empty name":        "",
		"name with a space": "validator 01",
		"non-ASCII name":    "validator-零一",
		"long name":         string(make([]byte, 256)),
	}

	for name, replicaName := range tests {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validator.Validate(&signerv2.SignRequest{
				Message:     []byte("message"),
				Metadata:    watermarkedMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 1, 0),
				ReplicaName: replicaName,
			}))
		})
	}
}

func TestSignRequestValidation_RejectsInvalidMetadata(t *testing.T) {
	validator, err := protovalidate.New()
	require.NoError(t, err)

	tests := map[string]*signerv2.SignRequest{
		"empty message": {
			Metadata:    watermarkedMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 1, 0),
			ReplicaName: "validator-01-a",
		},
		"missing metadata": {
			Message:     []byte("message"),
			ReplicaName: "validator-01-a",
		},
		"unspecified kind": {
			Message:     []byte("message"),
			Metadata:    watermarkedMetadata(signerv2.MessageKind_MESSAGE_KIND_UNSPECIFIED, 1, 0),
			ReplicaName: "validator-01-a",
		},
		"unknown kind": {
			Message:     []byte("message"),
			Metadata:    watermarkedMetadata(signerv2.MessageKind(99), 1, 0),
			ReplicaName: "validator-01-a",
		},
		"missing height": {
			Message:     []byte("message"),
			ReplicaName: "validator-01-a",
			Metadata: &signerv2.SigningMetadata{
				Kind:  signerv2.MessageKind_MESSAGE_KIND_PREVOTE,
				Round: proto.Uint64(0),
			},
		},
		"zero height": {
			Message:     []byte("message"),
			Metadata:    watermarkedMetadata(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, 0, 0),
			ReplicaName: "validator-01-a",
		},
		"missing round": {
			Message:     []byte("message"),
			ReplicaName: "validator-01-a",
			Metadata: &signerv2.SigningMetadata{
				Kind:   signerv2.MessageKind_MESSAGE_KIND_PREVOTE,
				Height: proto.Uint64(1),
			},
		},
		"validator proof with height": {
			Message:     []byte("message"),
			ReplicaName: "validator-01-a",
			Metadata: &signerv2.SigningMetadata{
				Kind:   signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF,
				Height: proto.Uint64(1),
			},
		},
		"validator proof with round": {
			Message:     []byte("message"),
			ReplicaName: "validator-01-a",
			Metadata: &signerv2.SigningMetadata{
				Kind:  signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF,
				Round: proto.Uint64(0),
			},
		},
		"telemetry with height": {
			Message: append([]byte("arc/telemetry/v1\x00"), make([]byte, 32)...),
			Metadata: &signerv2.SigningMetadata{
				Kind:   signerv2.MessageKind_MESSAGE_KIND_TELEMETRY,
				Height: proto.Uint64(1),
			},
		},
		"telemetry with round": {
			Message: append([]byte("arc/telemetry/v1\x00"), make([]byte, 32)...),
			Metadata: &signerv2.SigningMetadata{
				Kind:  signerv2.MessageKind_MESSAGE_KIND_TELEMETRY,
				Round: proto.Uint64(0),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validator.Validate(tt))
		})
	}
}
