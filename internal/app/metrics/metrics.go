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

// Package metrics provides the metrics for the app service.
package metrics

import "github.com/circlefin/arc-remote-signer/internal/common/metric"

const (
	// RequestTotalCounter is the total number of requests.
	RequestTotalCounter = "arc_remote_signer_request_total"

	// RequestTotalCounterSuccess is the total number of successful requests.
	RequestTotalCounterSuccess = "arc_remote_signer_request_total_success"

	// RequestTotalCounterError is the total number of error requests.
	RequestTotalCounterError = "arc_remote_signer_request_total_error"
)

var metrics = []metric.PrometheusMetric{
	{
		Name:   RequestTotalCounter,
		Help:   "Total number of signing requests",
		Type:   "counterVec",
		Labels: []string{"type"},
	},
	{
		Name:   RequestTotalCounterSuccess,
		Help:   "Total number of successful signing requests",
		Type:   "counterVec",
		Labels: []string{"type"},
	},
	{
		Name:   RequestTotalCounterError,
		Help:   "Total number of failed signing requests",
		Type:   "counterVec",
		Labels: []string{"type"},
	},
}
