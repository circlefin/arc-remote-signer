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

// Package metric provides Datadog-backed HTTP/API latency metrics used by this service.
//
// The exported API intentionally preserves naming and tag conventions that existing
// Datadog dashboards and monitors rely on (for example:
// `circle.platform_common_go.http.server` with `url_path` tags).
//
//go:generate mockgen -source $GOFILE -destination metric_mock.go -package $GOPACKAGE APIStatsService
package metric

import (
	"context"
	"strings"
	"time"
)

const (
	httpHandlerMetricName             = "http.handler"
	httpHandlerMetricNameDistribution = "http.server"
	httpHandlerURLPathTagKey          = "url_path"
	httpClientCircleCaller            = "caller"

	// DistributionsDisabled emits timing metrics only.
	DistributionsDisabled DistributionsOption = "distributionsDisabled"
	// DistributionsHybrid emits both timing and distribution metrics.
	DistributionsHybrid DistributionsOption = "distributionsHybrid"
	// DistributionsEnabled emits distribution metrics only.
	DistributionsEnabled DistributionsOption = "distributionsEnabled"
)

// StatsService defines the metric primitives required by this package.
type StatsService interface {
	Timing(name string, value time.Duration, tags []string)
	Distribution(name string, value int64, tags []string)
}

// CaptureLatencyRequest contains inputs for recording API latency metrics.
type CaptureLatencyRequest struct {
	Path    string
	Method  string
	Status  string
	Latency time.Duration
	// UserPrincipal is used as caller tag when present.
	UserPrincipal *string
	Tags          []string
}

// APIStatsService records inbound API request latency metrics.
type APIStatsService interface {
	CaptureLatency(ctx context.Context, req CaptureLatencyRequest)
}

// DistributionsOption controls whether timing/distribution metrics are emitted.
type DistributionsOption string

// FormatPath normalizes method/path into the metric `url_path` tag format.
// Distribution mode keeps Java-parity behavior for path params (`:` -> `_`).
func FormatPath(fullPath, method string, isDistribution bool) string {
	purgedPath := strings.Split(fullPath, "?")[0]
	replaceWith := ""
	if isDistribution {
		replaceWith = "_"
	}

	return strings.TrimRight(strings.ToLower(method)+"_"+strings.ReplaceAll(purgedPath, ":", replaceWith), ".")
}
