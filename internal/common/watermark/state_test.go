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
	"fmt"
	"maps"
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/replica"
	"github.com/stretchr/testify/require"
)

func TestAdvanceState_HostRejectsCandidateBeforeAnyConsensusStep(t *testing.T) {
	tests := map[string]struct {
		storedNamespace    Namespace
		storedTuple        Tuple
		candidateNamespace Namespace
		candidateTuple     Tuple
	}{
		"proposal at prevote tuple": {
			storedNamespace:    NamespacePrevotes,
			storedTuple:        Tuple{Height: 10, Round: 2, Rank: RankFirst},
			candidateNamespace: NamespaceProposals,
			candidateTuple:     Tuple{Height: 10, Round: 2, Rank: RankFirst},
		},
		"proposal below precommit": {
			storedNamespace:    NamespacePrecommits,
			storedTuple:        Tuple{Height: 10, Round: 2, Rank: RankFirst},
			candidateNamespace: NamespaceProposals,
			candidateTuple:     Tuple{Height: 10, Round: 1, Rank: RankFirst},
		},
		"prevote below proposal": {
			storedNamespace:    NamespaceProposals,
			storedTuple:        Tuple{Height: 10, Round: 2, Rank: RankFirst},
			candidateNamespace: NamespacePrevotes,
			candidateTuple:     Tuple{Height: 10, Round: 1, Rank: RankFirst},
		},
		"prevote at precommit tuple": {
			storedNamespace:    NamespacePrecommits,
			storedTuple:        Tuple{Height: 10, Round: 2, Rank: RankFirst},
			candidateNamespace: NamespacePrevotes,
			candidateTuple:     Tuple{Height: 10, Round: 2, Rank: RankFirst},
		},
		"precommit below prevote": {
			storedNamespace:    NamespacePrevotes,
			storedTuple:        Tuple{Height: 10, Round: 2, Rank: RankFirst},
			candidateNamespace: NamespacePrecommits,
			candidateTuple:     Tuple{Height: 10, Round: 1, Rank: RankFirst},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			state := State{
				tt.storedNamespace: {
					Tuple:       tt.storedTuple,
					MessageHash: HashMessage([]byte("stored")),
				},
			}
			candidate := Watermark{
				Tuple:       tt.candidateTuple,
				MessageHash: HashMessage([]byte("candidate")),
			}

			next, outcome, err := AdvanceState(
				state,
				tt.candidateNamespace,
				candidate,
				CrossKindHost,
			)

			require.ErrorIs(t, err, ErrWatermarkViolation)
			require.Zero(t, outcome)
			require.Equal(t, state, next)
		})
	}
}

func TestAdvanceState_EnclaveAllowsEqualPrecommitBoundary(t *testing.T) {
	state := State{
		NamespacePrecommits: testWatermark(10, 2, RankFirst, "precommit"),
	}
	candidate := testWatermark(10, 2, RankFirst, "prevote")

	next, outcome, err := AdvanceState(
		state,
		NamespacePrevotes,
		candidate,
		CrossKindEnclave,
	)

	require.NoError(t, err)
	require.Equal(t, OutcomeAdvanced, outcome)
	require.Equal(t, candidate, next[NamespacePrevotes])
	require.Equal(t, state[NamespacePrecommits], next[NamespacePrecommits])
}

func TestAdvanceState_EnclaveRejectsOlderCandidateForLaterConsensusStep(t *testing.T) {
	tests := map[string]struct {
		storedNamespace    Namespace
		candidateNamespace Namespace
	}{
		"proposal below prevote": {
			storedNamespace:    NamespacePrevotes,
			candidateNamespace: NamespaceProposals,
		},
		"proposal below precommit": {
			storedNamespace:    NamespacePrecommits,
			candidateNamespace: NamespaceProposals,
		},
		"prevote below precommit": {
			storedNamespace:    NamespacePrecommits,
			candidateNamespace: NamespacePrevotes,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			state := State{
				tt.storedNamespace: testWatermark(10, 2, RankFirst, "stored"),
			}

			next, outcome, err := AdvanceState(
				state,
				tt.candidateNamespace,
				testWatermark(10, 1, RankFirst, "candidate"),
				CrossKindEnclave,
			)

			require.ErrorIs(t, err, ErrWatermarkViolation)
			require.Zero(t, outcome)
			require.Equal(t, state, next)
		})
	}
}

func TestAdvanceState_EnclaveAllowsRestartBoundaries(t *testing.T) {
	tests := map[string]struct {
		storedNamespace    Namespace
		storedTuple        Tuple
		candidateNamespace Namespace
		candidateTuple     Tuple
	}{
		"proposal at prevote tuple": {
			storedNamespace:    NamespacePrevotes,
			storedTuple:        Tuple{Height: 10, Round: 2, Rank: RankFirst},
			candidateNamespace: NamespaceProposals,
			candidateTuple:     Tuple{Height: 10, Round: 2, Rank: RankFirst},
		},
		"precommit below prevote": {
			storedNamespace:    NamespacePrevotes,
			storedTuple:        Tuple{Height: 10, Round: 2, Rank: RankFirst},
			candidateNamespace: NamespacePrecommits,
			candidateTuple:     Tuple{Height: 10, Round: 1, Rank: RankFirst},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			state := State{
				tt.storedNamespace: {
					Tuple:       tt.storedTuple,
					MessageHash: HashMessage([]byte("stored")),
				},
			}
			candidate := Watermark{
				Tuple:       tt.candidateTuple,
				MessageHash: HashMessage([]byte("candidate")),
			}

			next, outcome, err := AdvanceState(
				state,
				tt.candidateNamespace,
				candidate,
				CrossKindEnclave,
			)

			require.NoError(t, err)
			require.Equal(t, OutcomeAdvanced, outcome)
			require.Equal(t, candidate, next[tt.candidateNamespace])
		})
	}
}

func TestAdvanceState_ExemptsProposalPartsFromConsensusStepOrdering(t *testing.T) {
	for _, mode := range []CrossKindMode{CrossKindHost, CrossKindEnclave} {
		for _, namespace := range []Namespace{NamespaceProposals, NamespacePrevotes, NamespacePrecommits} {
			t.Run(fmt.Sprintf("%d/%s", mode, namespace), func(t *testing.T) {
				stored := testWatermark(10, 2, RankFirst, "consensus")
				candidate := testWatermark(9, 1, RankFirst, "proposal-parts")
				next, outcome, err := AdvanceState(State{namespace: stored}, NamespaceProposalParts, candidate, mode)

				require.NoError(t, err)
				require.Equal(t, OutcomeAdvanced, outcome)
				require.Equal(t, State{namespace: stored, NamespaceProposalParts: candidate}, next)
			})
		}
	}
}

func TestAdvanceState_Transitions(t *testing.T) {
	stored := testWatermark(10, 2, RankFirst, "stored")
	tests := map[string]struct {
		state       State
		namespace   Namespace
		candidate   Watermark
		mode        CrossKindMode
		wantOutcome Outcome
		wantError   error
	}{
		"empty state": {
			namespace:   NamespacePrevotes,
			candidate:   stored,
			mode:        CrossKindHost,
			wantOutcome: OutcomeAdvanced,
		},
		"host accepts later step at equal tuple": {
			state:       State{NamespacePrevotes: stored},
			namespace:   NamespacePrecommits,
			candidate:   testWatermark(10, 2, RankFirst, "precommit"),
			mode:        CrossKindHost,
			wantOutcome: OutcomeAdvanced,
		},
		"host accepts precommit at proposal tuple": {
			state:       State{NamespaceProposals: stored},
			namespace:   NamespacePrecommits,
			candidate:   testWatermark(10, 2, RankFirst, "precommit"),
			mode:        CrossKindHost,
			wantOutcome: OutcomeAdvanced,
		},
		"host accepts prevote at proposal tuple": {
			state:       State{NamespaceProposals: stored},
			namespace:   NamespacePrevotes,
			candidate:   testWatermark(10, 2, RankFirst, "prevote"),
			mode:        CrossKindHost,
			wantOutcome: OutcomeAdvanced,
		},
		"height precedes round in ordering": {
			state:       State{NamespacePrecommits: testWatermark(10, ^uint64(0), RankFirst, "precommit")},
			namespace:   NamespaceProposals,
			candidate:   testWatermark(11, 0, RankFirst, "proposal"),
			mode:        CrossKindHost,
			wantOutcome: OutcomeAdvanced,
		},
		"host checks all stored kinds": {
			state:     State{NamespaceProposals: testWatermark(9, 0, RankFirst, "proposal"), NamespacePrecommits: stored},
			namespace: NamespacePrevotes,
			candidate: testWatermark(10, 1, RankFirst, "prevote"),
			mode:      CrossKindHost,
			wantError: ErrWatermarkViolation,
		},
		"enclave permits lower tuple after earlier step": {
			state:       State{NamespaceProposals: stored},
			namespace:   NamespacePrevotes,
			candidate:   testWatermark(9, 0, RankFirst, "prevote"),
			mode:        CrossKindEnclave,
			wantOutcome: OutcomeAdvanced,
		},
		"enclave checks all later steps": {
			state:     State{NamespacePrevotes: testWatermark(9, 0, RankFirst, "prevote"), NamespacePrecommits: stored},
			namespace: NamespaceProposals,
			candidate: testWatermark(10, 1, RankFirst, "proposal"),
			mode:      CrossKindEnclave,
			wantError: ErrWatermarkViolation,
		},
		"unknown candidate namespace": {
			namespace: Namespace("unknown"),
			candidate: stored,
			mode:      CrossKindHost,
			wantError: ErrInvalidCandidate,
		},
		"zero candidate height": {
			namespace: NamespacePrevotes,
			candidate: testWatermark(0, 0, RankFirst, "candidate"),
			mode:      CrossKindHost,
			wantError: ErrInvalidCandidate,
		},
		"missing candidate hash": {
			namespace: NamespacePrevotes,
			candidate: Watermark{Tuple: stored.Tuple},
			mode:      CrossKindHost,
			wantError: ErrInvalidCandidate,
		},
		"invalid candidate rank": {
			namespace: NamespacePrevotes,
			candidate: testWatermark(10, 2, Rank(1), "candidate"),
			mode:      CrossKindHost,
			wantError: ErrInvalidCandidate,
		},
		"unknown stored namespace": {
			state:     State{Namespace("unknown"): stored},
			namespace: NamespacePrevotes,
			candidate: stored,
			mode:      CrossKindHost,
			wantError: ErrWatermarkCorrupt,
		},
		"corrupt stored height": {
			state:     State{NamespacePrecommits: testWatermark(0, 0, RankFirst, "corrupt")},
			namespace: NamespacePrevotes,
			candidate: stored,
			mode:      CrossKindHost,
			wantError: ErrWatermarkCorrupt,
		},
		"corrupt stored hash": {
			state:     State{NamespacePrecommits: {Tuple: stored.Tuple}},
			namespace: NamespacePrevotes,
			candidate: stored,
			mode:      CrossKindHost,
			wantError: ErrWatermarkCorrupt,
		},
		"corrupt stored rank": {
			state:     State{NamespacePrecommits: testWatermark(10, 2, Rank(1), "corrupt")},
			namespace: NamespacePrevotes,
			candidate: stored,
			mode:      CrossKindHost,
			wantError: ErrWatermarkCorrupt,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			before := maps.Clone(tt.state)
			next, outcome, err := AdvanceState(tt.state, tt.namespace, tt.candidate, tt.mode)
			require.Equal(t, before, tt.state, "transition must not mutate its input")
			require.Equal(t, tt.wantOutcome, outcome)
			if tt.wantError != nil {
				require.ErrorIs(t, err, tt.wantError)
				require.True(t, maps.Equal(before, next), "a refusal must preserve every watermark")
			} else {
				require.NoError(t, err)
				want := make(State, len(before)+1)
				for namespace, watermark := range before {
					want[namespace] = watermark
				}
				want[tt.namespace] = tt.candidate
				require.Equal(t, want, next)
			}
			next[NamespaceProposalParts] = testWatermark(99, 0, RankFirst, "caller mutation")
			require.Equal(t, before, tt.state, "returned state must not alias the input")
		})
	}
}

func TestAdvanceState_SameKindRulesPrecedeCrossKindRules(t *testing.T) {
	stored := testWatermark(10, 2, RankFirst, "prevote")
	tests := map[string]struct {
		candidate   Watermark
		wantOutcome Outcome
		wantError   error
	}{
		"identical retry": {
			candidate:   stored,
			wantOutcome: OutcomeUnchanged,
		},
		"conflicting bytes": {
			candidate: testWatermark(10, 2, RankFirst, "conflict"),
			wantError: ErrWatermarkViolation,
		},
		"stale round": {
			candidate: testWatermark(10, 1, RankFirst, "stale"),
			wantError: ErrWatermarkStale,
		},
		"stale height": {
			candidate: testWatermark(9, ^uint64(0), RankFirst, "stale"),
			wantError: ErrWatermarkStale,
		},
	}
	for _, mode := range []CrossKindMode{CrossKindHost, CrossKindEnclave} {
		for name, tt := range tests {
			t.Run(fmt.Sprintf("%d/%s", mode, name), func(t *testing.T) {
				state := State{NamespacePrevotes: stored, NamespacePrecommits: testWatermark(11, 0, RankFirst, "newer precommit")}
				before := maps.Clone(state)
				next, outcome, err := AdvanceState(state, NamespacePrevotes, tt.candidate, mode)
				if tt.wantError != nil {
					require.ErrorIs(t, err, tt.wantError)
				} else {
					require.NoError(t, err)
				}
				require.Equal(t, tt.wantOutcome, outcome)
				require.Equal(t, before, state)
				require.Equal(t, before, next)
				next[NamespaceProposalParts] = testWatermark(99, 0, RankFirst, "caller mutation")
				require.Equal(t, before, state, "retry and refusal results must not alias the input")
			})
		}
	}
}

func TestAdvanceState_StoredProposalPartsDoNotRestrictConsensus(t *testing.T) {
	for _, mode := range []CrossKindMode{CrossKindHost, CrossKindEnclave} {
		for _, namespace := range []Namespace{NamespaceProposals, NamespacePrevotes, NamespacePrecommits} {
			t.Run(fmt.Sprintf("%d/%s", mode, namespace), func(t *testing.T) {
				stored := testWatermark(20, 0, RankFirst, "parts")
				candidate := testWatermark(10, 0, RankFirst, "consensus")
				next, outcome, err := AdvanceState(State{NamespaceProposalParts: stored}, namespace, candidate, mode)
				require.NoError(t, err)
				require.Equal(t, OutcomeAdvanced, outcome)
				require.Equal(t, State{NamespaceProposalParts: stored, namespace: candidate}, next)
			})
		}
	}
}

func TestAdvanceState_InvalidModeIsInternalError(t *testing.T) {
	for name, mode := range map[string]CrossKindMode{"zero": 0, "unknown": 3} {
		t.Run(name, func(t *testing.T) {
			_, _, err := AdvanceState(nil, NamespacePrevotes, testWatermark(10, 0, RankFirst, "candidate"), mode)
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrInvalidCandidate)
		})
	}
}

func TestAdvanceOwnedState_EnforcesOwnerAcrossNamespaces(t *testing.T) {
	replicaA, err := replica.NewID("replica-a")
	require.NoError(t, err)
	replicaB, err := replica.NewID("replica-b")
	require.NoError(t, err)
	state := State{
		NamespacePrevotes: testWatermark(10, 2, RankFirst, "prevote"),
	}
	ownership := Ownership{Height: 10, ReplicaName: replicaA.String()}

	_, _, _, err = AdvanceOwnedState(
		state,
		ownership,
		NamespacePrecommits,
		testWatermark(10, 3, RankFirst, "precommit"),
		replicaB,
	)
	require.ErrorIs(t, err, ErrWatermarkOwnerConflict)

	_, _, _, err = AdvanceOwnedState(
		state,
		ownership,
		NamespaceProposals,
		testWatermark(9, 0, RankFirst, "proposal"),
		replicaB,
	)
	require.ErrorIs(t, err, ErrWatermarkOwnerConflict, "owner conflict is the first matching row")

	next, nextOwnership, outcome, err := AdvanceOwnedState(
		state,
		ownership,
		NamespacePrecommits,
		testWatermark(11, 0, RankFirst, "precommit-11"),
		replicaB,
	)
	require.NoError(t, err)
	require.Equal(t, OutcomeAdvanced, outcome)
	require.Equal(t, uint64(11), nextOwnership.Height)
	require.Equal(t, replicaB.String(), nextOwnership.ReplicaName)
	require.Contains(t, next, NamespacePrevotes)
	require.Contains(t, next, NamespacePrecommits)
}
