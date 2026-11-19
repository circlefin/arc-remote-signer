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
)

// ClassifyWatermark compares a candidate with the current namespace watermark.
func ClassifyWatermark(namespace Namespace, candidate, current Watermark) (Outcome, error) {
	switch candidate.Tuple.Compare(current.Tuple) {
	case -1:
		return 0, fmt.Errorf(
			"%w: namespace=%s candidate=%s current=%s",
			ErrWatermarkStale,
			namespace,
			candidate.Tuple,
			current.Tuple,
		)
	case 1:
		return OutcomeAdvanced, nil
	default:
		if candidate.MessageHash != current.MessageHash {
			return 0, fmt.Errorf(
				"%w: namespace=%s tuple=%s candidate_hash=%x current_hash=%x",
				ErrWatermarkViolation,
				namespace,
				candidate.Tuple,
				candidate.MessageHash,
				current.MessageHash,
			)
		}
		return OutcomeUnchanged, nil
	}
}
