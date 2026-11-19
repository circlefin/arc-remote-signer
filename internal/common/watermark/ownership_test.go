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

	"github.com/circlefin/arc-remote-signer/internal/common/replica"
	"github.com/stretchr/testify/require"
)

func TestValidateOwnershipTransition(t *testing.T) {
	replicaA, err := replica.NewID("replica-a")
	require.NoError(t, err)
	replicaB, err := replica.NewID("replica-b")
	require.NoError(t, err)

	tests := map[string]struct {
		candidateHeight uint64
		candidateOwner  replica.ID
		current         Ownership
		wantError       error
	}{
		"higher height can change owner": {
			candidateHeight: 11,
			candidateOwner:  replicaB,
			current:         Ownership{Height: 10, ReplicaName: replicaA.String()},
		},
		"same height accepts current owner": {
			candidateHeight: 10,
			candidateOwner:  replicaA,
			current:         Ownership{Height: 10, ReplicaName: replicaA.String()},
		},
		"same height rejects different owner": {
			candidateHeight: 10,
			candidateOwner:  replicaB,
			current:         Ownership{Height: 10, ReplicaName: replicaA.String()},
			wantError:       ErrWatermarkOwnerConflict,
		},
		"same height unowned item accepts any replica": {
			candidateHeight: 10,
			candidateOwner:  replicaB,
			current:         Ownership{Height: 10},
		},
		"higher height unowned item accepts any replica": {
			candidateHeight: 11,
			candidateOwner:  replicaB,
			current:         Ownership{Height: 10},
		},
		"lower height accepts current owner": {
			candidateHeight: 9,
			candidateOwner:  replicaA,
			current:         Ownership{Height: 10, ReplicaName: replicaA.String()},
		},
		"lower height rejects different owner": {
			candidateHeight: 9,
			candidateOwner:  replicaB,
			current:         Ownership{Height: 10, ReplicaName: replicaA.String()},
			wantError:       ErrWatermarkOwnerConflict,
		},
		"lower height unowned state accepts any replica": {
			candidateHeight: 9,
			candidateOwner:  replicaB,
			current:         Ownership{Height: 10},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateOwnershipTransition(
				NamespacePrevotes,
				tt.candidateHeight,
				tt.candidateOwner,
				tt.current,
			)

			require.ErrorIs(t, err, tt.wantError)
		})
	}
}
