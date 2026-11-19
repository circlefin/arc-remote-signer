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

	"github.com/stretchr/testify/require"
)

func TestClassifyWatermark(t *testing.T) {
	current := testWatermark(10, 2, RankFirst, "current")
	tests := map[string]struct {
		candidate   Watermark
		wantOutcome Outcome
		wantError   error
	}{
		"newer tuple advances": {
			candidate:   testWatermark(11, 0, RankFirst, "newer"),
			wantOutcome: OutcomeAdvanced,
		},
		"older tuple is stale": {
			candidate: testWatermark(10, 1, RankFirst, "older"),
			wantError: ErrWatermarkStale,
		},
		"same tuple and hash is unchanged": {
			candidate:   current,
			wantOutcome: OutcomeUnchanged,
		},
		"same tuple and different hash is a violation": {
			candidate: testWatermark(10, 2, RankFirst, "conflict"),
			wantError: ErrWatermarkViolation,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			outcome, err := ClassifyWatermark(NamespacePrevotes, tt.candidate, current)

			if tt.wantError != nil {
				require.ErrorIs(t, err, tt.wantError)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantOutcome, outcome)
		})
	}
}
