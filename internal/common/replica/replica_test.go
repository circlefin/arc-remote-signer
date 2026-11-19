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

package replica

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewID(t *testing.T) {
	tests := map[string]struct {
		name    string
		wantErr error
	}{
		"simple name":       {name: "validator-01-a"},
		"URI name":          {name: "spiffe://circle/validators/validator-01/replicas/a"},
		"empty name":        {wantErr: ErrInvalidName},
		"name with a space": {name: "validator 01", wantErr: ErrInvalidName},
		"non-ASCII name":    {name: "validator-零一", wantErr: ErrInvalidName},
		"long name":         {name: strings.Repeat("a", maxNameLength+1), wantErr: ErrInvalidName},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := NewID(tt.name)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.name, got.String())
		})
	}
}

func TestFromContext(t *testing.T) {
	_, ok := FromContext(context.Background())
	require.False(t, ok)
	_, ok = FromContext(NewContext(context.Background(), ID{}))
	require.False(t, ok)

	want, err := NewID("validator-01-a")
	require.NoError(t, err)

	got, ok := FromContext(NewContext(context.Background(), want))
	require.True(t, ok)
	require.Equal(t, want, got)
}
