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

package watermark

import (
	"testing"

	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestCandidateFromSigningMetadata(t *testing.T) {
	message := []byte("message")
	height := uint64(10)
	round := uint64(2)

	tests := []struct {
		name          string
		metadata      *signerv2.SigningMetadata
		wantNamespace Namespace
		wantRank      Rank
		wantRequired  bool
		wantErrorPart string
	}{
		{
			name: "prevote",
			metadata: &signerv2.SigningMetadata{
				Kind:   signerv2.MessageKind_MESSAGE_KIND_PREVOTE,
				Height: &height,
				Round:  &round,
			},
			wantNamespace: NamespacePrevotes,
			wantRank:      RankFirst,
			wantRequired:  true,
		},
		{
			name: "precommit",
			metadata: &signerv2.SigningMetadata{
				Kind:   signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT,
				Height: &height,
				Round:  &round,
			},
			wantNamespace: NamespacePrecommits,
			wantRank:      RankFirst,
			wantRequired:  true,
		},
		{
			name: "proposal",
			metadata: &signerv2.SigningMetadata{
				Kind:   signerv2.MessageKind_MESSAGE_KIND_PROPOSAL,
				Height: &height,
				Round:  &round,
			},
			wantNamespace: NamespaceProposals,
			wantRank:      RankFirst,
			wantRequired:  true,
		},
		{
			name: "proposal parts",
			metadata: &signerv2.SigningMetadata{
				Kind:   signerv2.MessageKind_MESSAGE_KIND_PROPOSAL_PARTS,
				Height: &height,
				Round:  &round,
			},
			wantNamespace: NamespaceProposalParts,
			wantRank:      RankFirst,
			wantRequired:  true,
		},
		{
			name: "validator proof",
			metadata: &signerv2.SigningMetadata{
				Kind: signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF,
			},
		},
		{
			name: "telemetry",
			metadata: &signerv2.SigningMetadata{
				Kind: signerv2.MessageKind_MESSAGE_KIND_TELEMETRY,
			},
		},
		{
			name:     "nil metadata",
			metadata: nil,
		},
		{
			name:     "delegation",
			metadata: &signerv2.SigningMetadata{Kind: signerv2.MessageKind_MESSAGE_KIND_DELEGATION},
		},
		{
			name:          "delegation with height",
			metadata:      &signerv2.SigningMetadata{Kind: signerv2.MessageKind_MESSAGE_KIND_DELEGATION, Height: &height},
			wantErrorPart: "delegation",
		},
		{
			name:          "delegation with round",
			metadata:      &signerv2.SigningMetadata{Kind: signerv2.MessageKind_MESSAGE_KIND_DELEGATION, Round: &round},
			wantErrorPart: "delegation",
		},
		{
			name: "missing height",
			metadata: &signerv2.SigningMetadata{
				Kind:  signerv2.MessageKind_MESSAGE_KIND_PREVOTE,
				Round: &round,
			},
			wantErrorPart: "requires height and round",
		},
		{
			name: "missing round",
			metadata: &signerv2.SigningMetadata{
				Kind:   signerv2.MessageKind_MESSAGE_KIND_PREVOTE,
				Height: &height,
			},
			wantErrorPart: "requires height and round",
		},
		{
			name: "validator proof with height",
			metadata: &signerv2.SigningMetadata{
				Kind:   signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF,
				Height: &height,
			},
			wantErrorPart: "validator proof",
		},
		{
			name: "unknown kind",
			metadata: &signerv2.SigningMetadata{
				Kind:   signerv2.MessageKind(99),
				Height: &height,
				Round:  &round,
			},
			wantErrorPart: "unsupported message kind",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace, candidate, required, err := CandidateFromSigningMetadata(tt.metadata, message)

			if tt.wantErrorPart != "" {
				require.ErrorContains(t, err, tt.wantErrorPart)
				require.False(t, required)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantRequired, required)
			if !tt.wantRequired {
				require.Empty(t, namespace)
				require.Equal(t, Watermark{}, candidate)
				return
			}
			require.Equal(t, tt.wantNamespace, namespace)
			require.Equal(t, Tuple{
				Height: height,
				Round:  round,
				Rank:   tt.wantRank,
			}, candidate.Tuple)
			require.Equal(t, HashMessage(message), candidate.MessageHash)
		})
	}
}

func TestCandidateFromSigningMetadata_HashesExactMessage(t *testing.T) {
	metadata := &signerv2.SigningMetadata{
		Kind:   signerv2.MessageKind_MESSAGE_KIND_PREVOTE,
		Height: proto.Uint64(1),
		Round:  proto.Uint64(0),
	}

	_, first, required, err := CandidateFromSigningMetadata(metadata, []byte("first"))
	require.NoError(t, err)
	require.True(t, required)

	_, second, required, err := CandidateFromSigningMetadata(metadata, []byte("second"))
	require.NoError(t, err)
	require.True(t, required)
	require.NotEqual(t, first.MessageHash, second.MessageHash)
}
