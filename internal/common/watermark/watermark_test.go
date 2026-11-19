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
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashMessage_UsesSHA256(t *testing.T) {
	hash := HashMessage([]byte("message"))

	require.Equal(t, "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d", hex.EncodeToString(hash[:]))
}

func TestTupleCompare_LexicographicOrder(t *testing.T) {
	tests := map[string]struct {
		left  Tuple
		right Tuple
		want  int
	}{
		"equal": {
			left:  Tuple{Height: 10, Round: 2, Rank: 1},
			right: Tuple{Height: 10, Round: 2, Rank: 1},
		},
		"lower height": {
			left:  Tuple{Height: 9, Round: 10, Rank: 1},
			right: Tuple{Height: 10, Round: 0, Rank: 0},
			want:  -1,
		},
		"higher height": {
			left:  Tuple{Height: 11, Round: 0, Rank: 0},
			right: Tuple{Height: 10, Round: 10, Rank: 1},
			want:  1,
		},
		"lower round": {
			left:  Tuple{Height: 10, Round: 1, Rank: 1},
			right: Tuple{Height: 10, Round: 2, Rank: 0},
			want:  -1,
		},
		"higher round": {
			left:  Tuple{Height: 10, Round: 3, Rank: 0},
			right: Tuple{Height: 10, Round: 2, Rank: 1},
			want:  1,
		},
		"lower rank": {
			left:  Tuple{Height: 10, Round: 2, Rank: 0},
			right: Tuple{Height: 10, Round: 2, Rank: 1},
			want:  -1,
		},
		"higher rank": {
			left:  Tuple{Height: 10, Round: 2, Rank: 1},
			right: Tuple{Height: 10, Round: 2, Rank: 0},
			want:  1,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.left.Compare(tt.right))
		})
	}
}

func TestTupleString_FormatsDiagnosticValue(t *testing.T) {
	tuple := Tuple{Height: 10, Round: 2, Rank: Rank(1)}

	require.Equal(t, "(10,2,1)", tuple.String())
}
