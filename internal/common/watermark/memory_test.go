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
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func testWatermark(height, round uint64, rank Rank, message string) Watermark {
	return Watermark{
		Tuple: Tuple{
			Height: height,
			Round:  round,
			Rank:   rank,
		},
		MessageHash: HashMessage([]byte(message)),
	}
}

func TestMemoryRepository_ConcurrentConflictAllowsOneCandidate(t *testing.T) {
	repository := NewMemoryRepository()
	candidates := []Watermark{
		testWatermark(10, 2, RankFirst, "candidate-a"),
		testWatermark(10, 2, RankFirst, "candidate-b"),
	}
	type result struct {
		outcome Outcome
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, len(candidates))

	for _, candidate := range candidates {
		go func() {
			<-start
			outcome, err := repository.CompareAndAdvance(context.Background(), NamespacePrevotes, candidate)
			results <- result{outcome: outcome, err: err}
		}()
	}
	close(start)

	var advanced, violations int
	for range candidates {
		result := <-results
		switch {
		case result.err == nil:
			require.Equal(t, OutcomeAdvanced, result.outcome)
			advanced++
		case errors.Is(result.err, ErrWatermarkViolation):
			violations++
		default:
			require.NoError(t, result.err)
		}
	}
	require.Equal(t, 1, advanced)
	require.Equal(t, 1, violations)
}

func TestMemoryRepository_AdvancesNewerWatermarks(t *testing.T) {
	repository := NewMemoryRepository()

	outcome, err := repository.CompareAndAdvance(
		context.Background(),
		NamespacePrevotes,
		testWatermark(10, 2, RankFirst, "prevote"),
	)
	require.NoError(t, err)
	require.Equal(t, OutcomeAdvanced, outcome)

	// Precommits use an independent namespace and also advance at the same tuple.
	precommit := testWatermark(10, 2, RankFirst, "precommit")
	outcome, err = repository.CompareAndAdvance(
		context.Background(),
		NamespacePrecommits,
		precommit,
	)
	require.NoError(t, err)
	require.Equal(t, OutcomeAdvanced, outcome)

	// Prevote retry remains valid and unchanged.
	currentPrevote := testWatermark(10, 2, RankFirst, "prevote")
	outcome, err = repository.CompareAndAdvance(context.Background(), NamespacePrevotes, currentPrevote)
	require.NoError(t, err)
	require.Equal(t, OutcomeUnchanged, outcome)

	// Conflicting prevote at the same tuple is a violation.
	_, err = repository.CompareAndAdvance(
		context.Background(),
		NamespacePrevotes,
		testWatermark(10, 2, RankFirst, "conflict"),
	)
	require.ErrorIs(t, err, ErrWatermarkViolation)

	// Newer tuple advances prevotes.
	outcome, err = repository.CompareAndAdvance(
		context.Background(),
		NamespacePrevotes,
		testWatermark(11, 0, RankFirst, "prevote-11"),
	)
	require.NoError(t, err)
	require.Equal(t, OutcomeAdvanced, outcome)
}

func TestMemoryRepository_AcceptsIdenticalRetryWithoutAdvancing(t *testing.T) {
	repository := NewMemoryRepository()
	candidate := testWatermark(10, 2, RankFirst, "precommit")

	_, err := repository.CompareAndAdvance(context.Background(), NamespacePrecommits, candidate)
	require.NoError(t, err)

	outcome, err := repository.CompareAndAdvance(context.Background(), NamespacePrecommits, candidate)
	require.NoError(t, err)
	require.Equal(t, OutcomeUnchanged, outcome)
}

func TestMemoryRepository_RejectsDifferentMessageAtCurrentTuple(t *testing.T) {
	repository := NewMemoryRepository()
	current := testWatermark(10, 2, RankFirst, "current")
	conflict := testWatermark(10, 2, RankFirst, "conflict")

	_, err := repository.CompareAndAdvance(context.Background(), NamespacePrevotes, current)
	require.NoError(t, err)

	_, err = repository.CompareAndAdvance(context.Background(), NamespacePrevotes, conflict)
	require.ErrorIs(t, err, ErrWatermarkViolation)

	outcome, err := repository.CompareAndAdvance(context.Background(), NamespacePrevotes, current)
	require.NoError(t, err)
	require.Equal(t, OutcomeUnchanged, outcome)
}

func TestMemoryRepository_RejectsOlderTuple(t *testing.T) {
	repository := NewMemoryRepository()
	current := testWatermark(10, 2, RankFirst, "current")
	stale := testWatermark(10, 1, RankFirst, "stale")

	_, err := repository.CompareAndAdvance(context.Background(), NamespacePrevotes, current)
	require.NoError(t, err)

	_, err = repository.CompareAndAdvance(context.Background(), NamespacePrevotes, stale)
	require.ErrorIs(t, err, ErrWatermarkStale)

	outcome, err := repository.CompareAndAdvance(context.Background(), NamespacePrevotes, current)
	require.NoError(t, err)
	require.Equal(t, OutcomeUnchanged, outcome)
}

func TestMemoryRepository_RejectsPrevoteBelowPrecommit(t *testing.T) {
	repository := NewMemoryRepository()

	_, err := repository.CompareAndAdvance(
		context.Background(),
		NamespacePrecommits,
		testWatermark(10, 2, RankFirst, "precommit"),
	)
	require.NoError(t, err)

	_, err = repository.CompareAndAdvance(
		context.Background(),
		NamespacePrevotes,
		testWatermark(10, 1, RankFirst, "prevote"),
	)
	require.ErrorIs(t, err, ErrWatermarkViolation)
}

func TestMemoryRepository_AllowsPrevoteAtPrecommitAfterEmptyPrevoteState(t *testing.T) {
	repository := NewMemoryRepository()

	_, err := repository.CompareAndAdvance(
		context.Background(),
		NamespacePrecommits,
		testWatermark(10, 2, RankFirst, "precommit"),
	)
	require.NoError(t, err)

	outcome, err := repository.CompareAndAdvance(
		context.Background(),
		NamespacePrevotes,
		testWatermark(10, 2, RankFirst, "prevote"),
	)
	require.NoError(t, err)
	require.Equal(t, OutcomeAdvanced, outcome)
}

func TestMemoryRepository_IsolatesNamespaces(t *testing.T) {
	repository := NewMemoryRepository()
	tuple := Tuple{Height: 10, Round: 2, Rank: RankFirst}

	for namespace, message := range map[Namespace]string{
		NamespacePrevotes:      "prevote",
		NamespacePrecommits:    "precommit",
		NamespaceProposals:     "proposal",
		NamespaceProposalParts: "proposal-parts",
	} {
		outcome, err := repository.CompareAndAdvance(context.Background(), namespace, Watermark{
			Tuple:       tuple,
			MessageHash: HashMessage([]byte(message)),
		})
		require.NoError(t, err)
		require.Equal(t, OutcomeAdvanced, outcome)
	}
}

func TestMemoryRepository_RejectsInvalidCandidateWithoutMutation(t *testing.T) {
	tests := map[string]struct {
		namespace      Namespace
		candidate      Watermark
		validNamespace Namespace
		validCandidate Watermark
	}{
		"unknown namespace": {
			namespace:      Namespace("unknown"),
			candidate:      testWatermark(10, 2, RankFirst, "candidate"),
			validNamespace: NamespacePrevotes,
			validCandidate: testWatermark(10, 2, RankFirst, "candidate"),
		},
		"legacy votes namespace is unknown": {
			namespace:      Namespace("votes"),
			candidate:      testWatermark(10, 2, RankFirst, "candidate"),
			validNamespace: NamespacePrevotes,
			validCandidate: testWatermark(10, 2, RankFirst, "candidate"),
		},
		"invalid rank for prevotes": {
			namespace:      NamespacePrevotes,
			candidate:      testWatermark(10, 2, Rank(1), "candidate"),
			validNamespace: NamespacePrevotes,
			validCandidate: testWatermark(10, 2, RankFirst, "candidate"),
		},
		"invalid rank for precommits": {
			namespace:      NamespacePrecommits,
			candidate:      testWatermark(10, 2, Rank(1), "candidate"),
			validNamespace: NamespacePrecommits,
			validCandidate: testWatermark(10, 2, RankFirst, "candidate"),
		},
		"invalid rank for proposals": {
			namespace:      NamespaceProposals,
			candidate:      testWatermark(10, 2, Rank(1), "candidate"),
			validNamespace: NamespaceProposals,
			validCandidate: testWatermark(10, 2, RankFirst, "candidate"),
		},
		"invalid rank for proposal parts": {
			namespace:      NamespaceProposalParts,
			candidate:      testWatermark(10, 2, Rank(1), "candidate"),
			validNamespace: NamespaceProposalParts,
			validCandidate: testWatermark(10, 2, RankFirst, "candidate"),
		},
		"zero height": {
			namespace:      NamespacePrevotes,
			candidate:      testWatermark(0, 2, RankFirst, "candidate"),
			validNamespace: NamespacePrevotes,
			validCandidate: testWatermark(1, 2, RankFirst, "candidate"),
		},
		"zero message hash": {
			namespace: NamespacePrevotes,
			candidate: Watermark{
				Tuple: Tuple{Height: 10, Round: 2, Rank: RankFirst},
			},
			validNamespace: NamespacePrevotes,
			validCandidate: testWatermark(10, 2, RankFirst, "candidate"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			repository := NewMemoryRepository()

			_, err := repository.CompareAndAdvance(context.Background(), tt.namespace, tt.candidate)
			require.ErrorIs(t, err, ErrInvalidCandidate)

			outcome, err := repository.CompareAndAdvance(context.Background(), tt.validNamespace, tt.validCandidate)
			require.NoError(t, err)
			require.Equal(t, OutcomeAdvanced, outcome)
		})
	}
}
