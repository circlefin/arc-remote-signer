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
)

type apiStatsService struct {
	statsService        StatsService
	distributionsOption DistributionsOption
}

// APIStatsOption customizes APIStatsService behavior.
type APIStatsOption func(*apiStatsService)

// WithDistributionsOption configures whether API latency emits timing metrics,
// distribution metrics, or both.
func WithDistributionsOption(option DistributionsOption) APIStatsOption {
	return func(s *apiStatsService) {
		s.distributionsOption = option
	}
}

// NewAPIStatsServiceImpl constructs an APIStatsService from the provided stats
// backend and options.
func NewAPIStatsServiceImpl(statsService StatsService, opts ...APIStatsOption) APIStatsService {
	svc := &apiStatsService{
		statsService:        statsService,
		distributionsOption: DistributionsDisabled,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

func (s *apiStatsService) CaptureLatency(_ context.Context, req CaptureLatencyRequest) {
	tags := []string{"status:" + req.Status}

	if req.UserPrincipal != nil && len(*req.UserPrincipal) > 0 {
		tags = append(tags, httpClientCircleCaller+":"+*req.UserPrincipal)
	}

	if len(req.Tags) > 0 {
		tags = append(tags, req.Tags...)
	}

	if s.distributionsOption == DistributionsEnabled || s.distributionsOption == DistributionsHybrid {
		distributionTags := append([]string{httpHandlerURLPathTagKey + ":" + FormatPath(req.Path, req.Method, true)}, tags...)
		s.statsService.Distribution(httpHandlerMetricNameDistribution, req.Latency.Milliseconds(), distributionTags)
	}
	if s.distributionsOption == DistributionsDisabled || s.distributionsOption == DistributionsHybrid {
		timingTags := append(tags, httpHandlerURLPathTagKey+":"+FormatPath(req.Path, req.Method, false))
		s.statsService.Timing(httpHandlerMetricName, req.Latency, timingTags)
	}
}
