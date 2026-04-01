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

// Package interceptor provides a set of middleware for the grpc service.
package interceptor

import (
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/internal/common/metric"
	"google.golang.org/grpc"
)

var _logger *logging.Logger

func getLogger() *logging.Logger {
	if _logger != nil {
		return _logger
	}
	_logger = logging.Get("common.middleware")
	return _logger
}

// WithRecovery returns a unary server interceptor that recovers from panics and returns a status error.
func WithRecovery() grpc.UnaryServerInterceptor {
	return recoveryWithLogger(getLogger())
}

// WithRequestID returns a unary server interceptor that adds a request ID to the context.
func WithRequestID() grpc.UnaryServerInterceptor {
	return requestID()
}

// WithMetrics returns a unary server interceptor that captures metrics for gRPC requests.
func WithMetrics(apiStatsService metric.APIStatsService, opts ...MetricsOption) grpc.UnaryServerInterceptor {
	return Metrics(apiStatsService, opts...)
}

// WithLogging returns a unary server interceptor that logs the request and response.
func WithLogging() grpc.UnaryServerInterceptor {
	return loggingWithLogger(getLogger())
}
