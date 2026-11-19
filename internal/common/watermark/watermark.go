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

//go:generate mockgen -source=watermark.go -destination=watermark_mock.go -package=watermark

// Package watermark defines storage-independent watermark and ownership rules.
package watermark

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/circlefin/arc-remote-signer/internal/common/replica"
)

var (
	// ErrInvalidCandidate indicates a watermark outside the domain contract.
	ErrInvalidCandidate = errors.New("invalid watermark candidate")
	// ErrWatermarkViolation indicates conflicting bytes or invalid cross-kind ordering.
	ErrWatermarkViolation = errors.New("watermark violation")
	// ErrWatermarkStale indicates a tuple below the current watermark.
	ErrWatermarkStale = errors.New("watermark stale")
	// ErrWatermarkOwnerConflict indicates a request from a different replica at
	// or below the highest owned height across all namespaces.
	ErrWatermarkOwnerConflict = errors.New("watermark owner conflict")
	// ErrWatermarkIndeterminate indicates that a failed write may have committed.
	ErrWatermarkIndeterminate = errors.New("watermark condition result indeterminate")
	// ErrWatermarkCorrupt indicates that persisted watermark state violates the storage contract.
	ErrWatermarkCorrupt = errors.New("watermark corrupt")
)

// Namespace separates messages that may validly share a height and round.
type Namespace string

const (
	// NamespacePrevotes contains prevotes.
	NamespacePrevotes Namespace = "prevotes"
	// NamespacePrecommits contains precommits.
	NamespacePrecommits Namespace = "precommits"
	// NamespaceProposals contains formal proposals.
	NamespaceProposals Namespace = "proposals"
	// NamespaceProposalParts contains proposal-parts hashes.
	NamespaceProposalParts Namespace = "proposal-parts"
)

// MessageHash identifies the exact message bytes associated with a tuple.
type MessageHash [sha256.Size]byte

// HashMessage hashes the exact bytes that the signer will sign.
func HashMessage(message []byte) MessageHash {
	return sha256.Sum256(message)
}

// Rank is retained in the persisted tuple. All current namespaces require RankFirst.
type Rank uint8

// RankFirst is the only valid rank for current namespaces.
const RankFirst Rank = 0

// Tuple is a lexicographically ordered consensus position.
type Tuple struct {
	Height uint64
	Round  uint64
	Rank   Rank
}

// Compare returns -1, 0, or 1 when t is before, equal to, or after other.
func (t Tuple) Compare(other Tuple) int {
	if result := cmp.Compare(t.Height, other.Height); result != 0 {
		return result
	}
	if result := cmp.Compare(t.Round, other.Round); result != 0 {
		return result
	}
	return cmp.Compare(t.Rank, other.Rank)
}

// String formats a tuple for diagnostic output.
func (t Tuple) String() string {
	return fmt.Sprintf("(%d,%d,%d)", t.Height, t.Round, t.Rank)
}

// Watermark associates a consensus tuple with the exact message bytes signed there.
type Watermark struct {
	Tuple       Tuple
	MessageHash MessageHash
}

// Validate verifies that a candidate belongs to the namespace's domain.
func (w Watermark) Validate(namespace Namespace) error {
	if w.Tuple.Height == 0 {
		return fmt.Errorf("%w: height must be greater than zero", ErrInvalidCandidate)
	}
	if w.MessageHash == (MessageHash{}) {
		return fmt.Errorf("%w: message hash is required", ErrInvalidCandidate)
	}

	switch namespace {
	case NamespacePrevotes, NamespacePrecommits, NamespaceProposals, NamespaceProposalParts:
		if w.Tuple.Rank != RankFirst {
			return fmt.Errorf("%w: invalid %s rank %d", ErrInvalidCandidate, namespace, w.Tuple.Rank)
		}
	default:
		return fmt.Errorf("%w: unknown namespace %q", ErrInvalidCandidate, namespace)
	}

	return nil
}

// Outcome describes a successful compare-and-advance operation.
type Outcome uint8

const (
	// OutcomeAdvanced indicates that the candidate became the new watermark.
	OutcomeAdvanced Outcome = iota + 1
	// OutcomeUnchanged indicates an idempotent retry of the current watermark.
	OutcomeUnchanged
)

// Repository atomically compares and advances one validator's namespace watermarks.
// A non-nil error can follow a committed write. The caller must retry with the
// exact same candidate until it receives a confirmed outcome.
type Repository interface {
	CompareAndAdvance(context.Context, Namespace, Watermark) (Outcome, error)
}

// OwnedAdvancer compares and advances one validator's aggregate watermark
// state. One replica owns the highest height across all namespaces.
type OwnedAdvancer interface {
	CompareAndAdvance(context.Context, Namespace, Watermark, replica.ID) (Outcome, error)
}
