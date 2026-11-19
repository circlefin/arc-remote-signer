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

	"github.com/circlefin/arc-remote-signer/internal/common/replica"
)

// State holds the namespace watermarks for one validator.
type State map[Namespace]Watermark

// CrossKindMode selects the host or enclave cross-kind ordering rule.
type CrossKindMode uint8

const (
	// CrossKindHost applies the durable host's full tuple-and-step ordering.
	CrossKindHost CrossKindMode = iota + 1
	// CrossKindEnclave applies the enclave's strict tuple ordering against
	// later steps. It preserves valid equal-tuple retries after an enclave restart.
	CrossKindEnclave
)

var consensusNamespaces = [...]Namespace{
	NamespaceProposals,
	NamespacePrevotes,
	NamespacePrecommits,
}

// AdvanceState applies same-kind and cross-kind rules without replica ownership.
// It returns a copy and never mutates current.
func AdvanceState(
	current State,
	namespace Namespace,
	candidate Watermark,
	crossKindMode CrossKindMode,
) (State, Outcome, error) {
	next := current.clone()
	if err := candidate.Validate(namespace); err != nil {
		return next, 0, err
	}
	if err := current.Validate(); err != nil {
		return next, 0, err
	}
	if crossKindMode != CrossKindHost && crossKindMode != CrossKindEnclave {
		return next, 0, fmt.Errorf("unknown cross-kind mode %d", crossKindMode)
	}

	if stored, ok := current[namespace]; ok {
		outcome, err := ClassifyWatermark(namespace, candidate, stored)
		if err != nil || outcome == OutcomeUnchanged {
			return next, outcome, err
		}
	}

	if storedNamespace, stored, violation := findCrossKindViolation(
		current,
		namespace,
		candidate.Tuple,
		crossKindMode,
	); violation {
		return next, 0, fmt.Errorf(
			"%w: candidate %s=%s precedes %s=%s",
			ErrWatermarkViolation,
			namespace,
			candidate.Tuple,
			storedNamespace,
			stored.Tuple,
		)
	}

	next[namespace] = candidate
	return next, OutcomeAdvanced, nil
}

// AdvanceOwnedState applies the host rule table, including the first matching
// per-height replica ownership row.
func AdvanceOwnedState(
	current State,
	ownership Ownership,
	namespace Namespace,
	candidate Watermark,
	candidateOwner replica.ID,
) (State, Ownership, Outcome, error) {
	if candidateOwner == (replica.ID{}) {
		return current.clone(), ownership, 0, fmt.Errorf(
			"%w: replica identity is required",
			ErrInvalidCandidate,
		)
	}
	if err := ValidateOwnershipTransition(namespace, candidate.Tuple.Height, candidateOwner, ownership); err != nil {
		return current.clone(), ownership, 0, err
	}

	next, outcome, err := AdvanceState(current, namespace, candidate, CrossKindHost)
	if err != nil {
		return next, ownership, 0, err
	}

	nextOwnership := ownership
	if nextOwnership.ReplicaName == "" || candidate.Tuple.Height > nextOwnership.Height {
		nextOwnership = Ownership{
			Height:      candidate.Tuple.Height,
			ReplicaName: candidateOwner.String(),
		}
	}
	return next, nextOwnership, outcome, nil
}

// Validate checks every stored namespace watermark.
func (s State) Validate() error {
	for namespace, stored := range s {
		if err := stored.Validate(namespace); err != nil {
			return fmt.Errorf("%w: namespace=%s: %v", ErrWatermarkCorrupt, namespace, err)
		}
	}
	return nil
}

func (s State) clone() State {
	clone := make(State, len(s)+1)
	for namespace, stored := range s {
		clone[namespace] = stored
	}
	return clone
}

func findCrossKindViolation(
	current State,
	candidateNamespace Namespace,
	candidateTuple Tuple,
	crossKindMode CrossKindMode,
) (Namespace, Watermark, bool) {
	candidateStep, ordered := consensusStep(candidateNamespace)
	if !ordered {
		return "", Watermark{}, false
	}

	for _, storedNamespace := range consensusNamespaces {
		stored, ok := current[storedNamespace]
		if !ok || storedNamespace == candidateNamespace {
			continue
		}

		storedStep, _ := consensusStep(storedNamespace)
		comparison := candidateTuple.Compare(stored.Tuple)
		switch crossKindMode {
		case CrossKindHost:
			if comparison < 0 || comparison == 0 && candidateStep < storedStep {
				return storedNamespace, stored, true
			}
		case CrossKindEnclave:
			if storedStep > candidateStep && comparison < 0 {
				return storedNamespace, stored, true
			}
		}
	}

	return "", Watermark{}, false
}

func consensusStep(namespace Namespace) (uint8, bool) {
	switch namespace {
	case NamespaceProposals:
		return 0, true
	case NamespacePrevotes:
		return 1, true
	case NamespacePrecommits:
		return 2, true
	default:
		return 0, false
	}
}
