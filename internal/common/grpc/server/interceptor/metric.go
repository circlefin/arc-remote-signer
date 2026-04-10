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

package interceptor

import (
	"context"
	"strconv"
	"time"

	"github.com/circlefin/arc-remote-signer/internal/common/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MetricsConfig holds the configuration for metrics middleware.
type MetricsConfig struct {
	ExtractTagsFromGRPC ExtractTagsFromGRPC
}

// ExtractTagsFromGRPC extracts tags from gRPC context.
// Tags should follow the "key:value" format to be compatible with the stats service.
type ExtractTagsFromGRPC func(ctx context.Context, info *grpc.UnaryServerInfo) []string

// MetricsOption is the option that modifies MetricsConfig.
type MetricsOption func(*MetricsConfig)

// WithExtractTagsFromCtx sets the custom tag extraction function.
func WithExtractTagsFromCtx(f ExtractTagsFromGRPC) MetricsOption {
	return func(cfg *MetricsConfig) {
		cfg.ExtractTagsFromGRPC = f
	}
}

// Metrics returns a gRPC unary interceptor that records request latency and status
// metrics for each RPC call using the provided APIStatsService.
func Metrics(apiStatsService metric.APIStatsService, opts ...MetricsOption) grpc.UnaryServerInterceptor {
	if apiStatsService == nil {
		statsService := metric.GetStatsService()
		apiStatsService = metric.NewAPIStatsServiceImpl(statsService)
	}

	cfg := MetricsConfig{}
	for _, o := range opts {
		o(&cfg)
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		start := time.Now()

		// Call the handler
		resp, err = handler(ctx, req)

		// Calculate latency
		latency := time.Since(start)

		// Determine status code
		statusCode := codes.OK
		if err != nil {
			if st, ok := status.FromError(err); ok {
				statusCode = st.Code()
			} else {
				statusCode = codes.Unknown
			}
		}

		// Extract method and path from gRPC info
		method := info.FullMethod
		path := method // For gRPC, the method is the path

		// Extract tags if provided
		var tags []string
		if cfg.ExtractTagsFromGRPC != nil {
			tags = cfg.ExtractTagsFromGRPC(ctx, info)
		}

		// Capture metrics
		apiStatsService.CaptureLatency(ctx, metric.CaptureLatencyRequest{
			Path:    path,
			Method:  method,
			Status:  strconv.Itoa(int(statusCode)),
			Latency: latency,
			Tags:    tags,
		})

		return resp, err
	}
}
