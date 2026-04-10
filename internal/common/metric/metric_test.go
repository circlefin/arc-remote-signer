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

package metric

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

func TestSetAndGetStatsService_RoundTrip(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStatsService := NewMockStatsService(ctrl)

	previous := GetStatsService()
	t.Cleanup(func() {
		SetStatsService(previous)
	})

	require.NotEqual(t, mockStatsService, GetStatsService())
	SetStatsService(mockStatsService)
	require.Equal(t, mockStatsService, GetStatsService())
}

func TestFormatPath(t *testing.T) {
	tests := []struct {
		name             string
		fullPath, method string
		wantTiming       string
		wantDist         string
	}{
		{
			name:       "timing removes colon and distribution replaces colon",
			fullPath:   "/v1/sign/:id",
			method:     "POST",
			wantTiming: "post_/v1/sign/id",
			wantDist:   "post_/v1/sign/_id",
		},
		{
			name:       "drops query parameters",
			fullPath:   "/v1/sign/:id?a=b&c=d",
			method:     "GET",
			wantTiming: "get_/v1/sign/id",
			wantDist:   "get_/v1/sign/_id",
		},
		{
			name:       "lowercases method only",
			fullPath:   "/V1/SIGN",
			method:     "PoSt",
			wantTiming: "post_/V1/SIGN",
			wantDist:   "post_/V1/SIGN",
		},
		{
			name:       "trims trailing dot",
			fullPath:   "/v1/sign.",
			method:     "GET",
			wantTiming: "get_/v1/sign",
			wantDist:   "get_/v1/sign",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			gotTiming := FormatPath(tt.fullPath, tt.method, false)
			gotDist := FormatPath(tt.fullPath, tt.method, true)
			require.Equal(t, tt.wantTiming, gotTiming)
			require.Equal(t, tt.wantDist, gotDist)
		})
	}
}
