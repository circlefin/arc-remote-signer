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
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
)

func TestHTTPClientStats_CaptureLatency_WithoutProviderName(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStats := NewMockStatsService(ctrl)
	svc := NewHTTPClientStatsServiceImpl(mockStats)

	ctx := context.Background()
	expectedTags := []string{
		"provider:NA",
		"status:200",
		"url_path:get_/v1/attest",
	}
	mockStats.EXPECT().
		Timing("http.client", 8*time.Millisecond, gomock.InAnyOrder(expectedTags)).
		Times(1)

	svc.CaptureLatency(ctx, "/v1/attest", "GET", "200", 8*time.Millisecond)
}

func TestHTTPClientStats_CaptureLatency_WithProviderName(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStats := NewMockStatsService(ctrl)
	svc := NewHTTPClientStatsServiceImpl(mockStats, WithProviderNameOption("enclave"))

	ctx := context.Background()
	expectedTags := []string{
		"provider:enclave",
		"status:200",
		"url_path:get_/v1/attest",
	}
	mockStats.EXPECT().
		Timing("http.client", 8*time.Millisecond, gomock.InAnyOrder(expectedTags)).
		Times(1)

	svc.CaptureLatency(ctx, "/v1/attest", "GET", "200", 8*time.Millisecond)
}
