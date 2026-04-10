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
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
)

func TestAPIStats_CaptureLatency_DistributionsDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStats := NewMockStatsService(ctrl)
	svc := NewAPIStatsServiceImpl(mockStats)

	ctx := context.Background()
	duration := 25 * time.Millisecond
	expectedTags := []string{
		"status:200",
		"url_path:post_/v1/sign",
	}
	mockStats.EXPECT().
		Timing(gomock.Eq("http.handler"), duration, gomock.InAnyOrder(expectedTags)).
		Times(1)

	svc.CaptureLatency(ctx, CaptureLatencyRequest{
		Path:    "/v1/sign",
		Method:  "POST",
		Status:  "200",
		Latency: duration,
	})
}

func TestAPIStats_CaptureLatency_DistributionsDisabledWithEntityTag(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStats := NewMockStatsService(ctrl)
	svc := NewAPIStatsServiceImpl(mockStats)

	ctx := context.Background()
	duration := 10 * time.Millisecond
	expectedTags := []string{
		"status:200",
		"url_path:post_/v1/sign",
	}
	mockStats.EXPECT().
		Timing(gomock.Eq("http.handler"), duration, gomock.InAnyOrder(expectedTags)).
		Times(1)

	svc.CaptureLatency(ctx, CaptureLatencyRequest{
		Path:    "/v1/sign",
		Method:  "POST",
		Status:  "200",
		Latency: duration,
	})
}

func TestAPIStats_CaptureLatency_DistributionsHybrid(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStats := NewMockStatsService(ctrl)
	svc := NewAPIStatsServiceImpl(mockStats, WithDistributionsOption(DistributionsHybrid))

	userPrincipal := "callerAuth"
	ctx := context.Background()
	duration := time.Duration(1000)
	timingTags := []string{
		"status:201",
		"caller:callerAuth",
		"url_path:post_/v1/sign/id",
	}
	distributionTags := []string{
		"url_path:post_/v1/sign/_id",
		"status:201",
		"caller:callerAuth",
	}
	mockStats.EXPECT().
		Timing(gomock.Eq("http.handler"), duration, gomock.InAnyOrder(timingTags)).
		Times(1)
	mockStats.EXPECT().
		Distribution(gomock.Eq("http.server"), duration.Milliseconds(), gomock.InAnyOrder(distributionTags)).
		Times(1)

	svc.CaptureLatency(ctx, CaptureLatencyRequest{
		Path:          "/v1/sign/:id",
		Method:        "post",
		Status:        "201",
		Latency:       duration,
		UserPrincipal: &userPrincipal,
	})
}

func TestAPIStats_CaptureLatency_DistributionsEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStats := NewMockStatsService(ctrl)
	svc := NewAPIStatsServiceImpl(mockStats, WithDistributionsOption(DistributionsEnabled))

	userPrincipal := "callerAuth"
	ctx := context.Background()
	duration := time.Duration(1000)
	expectedTags := []string{
		"url_path:post_/api/v1/users/_id",
		"status:201",
		"caller:callerAuth",
	}
	mockStats.EXPECT().
		Distribution(gomock.Eq("http.server"), duration.Milliseconds(), gomock.InAnyOrder(expectedTags)).
		Times(1)

	svc.CaptureLatency(ctx, CaptureLatencyRequest{
		Path:          "/api/v1/users/:id",
		Method:        "post",
		Status:        "201",
		Latency:       duration,
		UserPrincipal: &userPrincipal,
	})
}

func TestAPIStats_CaptureLatency_WithTags(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStats := NewMockStatsService(ctrl)
	userPrincipal := "callerAuth"

	for _, tt := range []struct {
		opt    DistributionsOption
		timing bool
		dist   bool
	}{
		{DistributionsHybrid, true, true},
		{DistributionsDisabled, true, false},
		{DistributionsEnabled, false, true},
	} {
		tt := tt
		t.Run(fmt.Sprintf("with %s", tt.opt), func(_ *testing.T) {
			svc := NewAPIStatsServiceImpl(mockStats, WithDistributionsOption(tt.opt))
			ctx := context.Background()
			duration := time.Duration(1000)
			baseTags := []string{
				"status:201",
				"caller:callerAuth",
			}
			additionalTags := []string{"tag1:val1", "tag2:val2"}
			if tt.timing {
				timingTags := append([]string{}, baseTags...)
				timingTags = append(timingTags, additionalTags...)
				timingTags = append(timingTags, "url_path:post_/api/v1/users/id")
				mockStats.EXPECT().
					Timing(
						gomock.Eq("http.handler"),
						duration,
						gomock.InAnyOrder(timingTags),
					).
					Times(1)
			}
			if tt.dist {
				distributionTags := []string{"url_path:post_/api/v1/users/_id"}
				distributionTags = append(distributionTags, baseTags...)
				distributionTags = append(distributionTags, additionalTags...)
				mockStats.EXPECT().
					Distribution(
						gomock.Eq("http.server"),
						duration.Milliseconds(),
						gomock.InAnyOrder(distributionTags),
					).
					Times(1)
			}
			svc.CaptureLatency(ctx, CaptureLatencyRequest{
				Path:          "/api/v1/users/:id",
				Method:        "post",
				Status:        "201",
				Latency:       duration,
				UserPrincipal: &userPrincipal,
				Tags:          additionalTags,
			})
		})
	}
}
