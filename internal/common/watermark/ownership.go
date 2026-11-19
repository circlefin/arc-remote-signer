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

// Ownership is the replica that owns the highest signed height.
// An empty ReplicaName shows that the state has no owner.
type Ownership struct {
	Height      uint64
	ReplicaName string
}

// ValidateOwnershipTransition checks a candidate against the per-height owner.
func ValidateOwnershipTransition(
	namespace Namespace,
	candidateHeight uint64,
	candidateOwner replica.ID,
	current Ownership,
) error {
	if current.ReplicaName != "" &&
		candidateHeight <= current.Height &&
		current.ReplicaName != candidateOwner.String() {
		return fmt.Errorf(
			"%w: namespace=%s candidate_height=%d owner_height=%d owner=%s candidate_replica=%s",
			ErrWatermarkOwnerConflict,
			namespace,
			candidateHeight,
			current.Height,
			current.ReplicaName,
			candidateOwner.String(),
		)
	}
	return nil
}
