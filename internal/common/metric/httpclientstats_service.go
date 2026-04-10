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
	"time"
)

const httpClientMetricName = "http.client"

// HTTPClientStatsService records outbound HTTP client latency metrics.
type HTTPClientStatsService interface {
	CaptureLatency(ctx context.Context, path, method, status string, latency time.Duration)
}

type httpClientStatsServiceImpl struct {
	stats        StatsService
	providerName string
}

// HTTPClientStatsOption customizes HTTPClientStatsService behavior.
type HTTPClientStatsOption func(*httpClientStatsServiceImpl)

// WithProviderNameOption sets the provider tag emitted for HTTP client metrics.
func WithProviderNameOption(providerName string) HTTPClientStatsOption {
	return func(s *httpClientStatsServiceImpl) {
		if providerName != "" {
			s.providerName = providerName
		}
	}
}

// NewHTTPClientStatsServiceImpl creates an immutable HTTP client metrics service.
// When statsService is nil, the global StatsService singleton is used.
func NewHTTPClientStatsServiceImpl(statsService StatsService, opts ...HTTPClientStatsOption) HTTPClientStatsService {
	if statsService == nil {
		statsService = GetStatsService()
	}
	svc := &httpClientStatsServiceImpl{
		stats:        statsService,
		providerName: "NA",
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// CaptureLatency records outbound HTTP latency with stable tags used by existing
// Datadog queries.
func (s *httpClientStatsServiceImpl) CaptureLatency(_ context.Context, path, method, status string, latency time.Duration) {
	tags := []string{
		"provider:" + s.providerName,
		"status:" + status,
		httpHandlerURLPathTagKey + ":" + FormatPath(path, method, false),
	}
	s.stats.Timing(httpClientMetricName, latency, tags)
}
