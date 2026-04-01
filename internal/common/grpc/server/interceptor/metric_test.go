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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestWithMetrics(t *testing.T) {
	// Test extract tags function
	extractTags := func(_ context.Context, info *grpc.UnaryServerInfo) []string {
		return []string{"test:tag", "method:" + info.FullMethod}
	}

	interceptor := WithMetrics(nil, WithExtractTagsFromCtx(extractTags))
	require.NotNil(t, interceptor)

	testCases := map[string]struct {
		setupContext func() context.Context
		request      interface{}
		info         *grpc.UnaryServerInfo
		handler      func(ctx context.Context, req interface{}) (interface{}, error)
		expectError  bool
	}{
		"successful request with metrics": {
			setupContext: func() context.Context {
				return context.Background()
			},
			request: "test-request",
			info:    &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"},
			handler: func(_ context.Context, _ interface{}) (interface{}, error) {
				// Simulate some processing time
				time.Sleep(1 * time.Millisecond)
				return "success", nil
			},
			expectError: false,
		},
		"failed request with metrics": {
			setupContext: func() context.Context {
				return context.Background()
			},
			request: "test-request",
			info:    &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"},
			handler: func(_ context.Context, _ interface{}) (interface{}, error) {
				return nil, status.Error(codes.Internal, "internal error")
			},
			expectError: true,
		},
		"request with nil extract tags": {
			setupContext: func() context.Context {
				return context.Background()
			},
			request: "test-request",
			info:    &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"},
			handler: func(_ context.Context, _ interface{}) (interface{}, error) {
				return "success", nil
			},
			expectError: false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := tc.setupContext()

			// Use nil extract tags for the third test case
			var testInterceptor grpc.UnaryServerInterceptor
			if name == "request with nil extract tags" {
				testInterceptor = WithMetrics(nil)
			} else {
				testInterceptor = interceptor
			}

			resp, err := testInterceptor(ctx, tc.request, tc.info, tc.handler)

			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, "success", resp)
			}
		})
	}
}

func TestWithMetricsNilStatsService(t *testing.T) {
	// Test that WithMetrics works with nil stats service
	interceptor := WithMetrics(nil)
	require.NotNil(t, interceptor)

	ctx := context.Background()
	req := "test-request"
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return "success", nil
	}

	resp, err := interceptor(ctx, req, info, handler)
	require.NoError(t, err)
	require.Equal(t, "success", resp)
}

func TestWithMetricsMultipleOptions(t *testing.T) {
	// Test that WithMetrics works with multiple options
	extractTags1 := func(_ context.Context, _ *grpc.UnaryServerInfo) []string {
		return []string{"option1:value1"}
	}

	extractTags2 := func(_ context.Context, _ *grpc.UnaryServerInfo) []string {
		return []string{"option2:value2"}
	}

	// Note: In the current implementation, only the last option will be used
	// since we're overwriting the same field in the config
	interceptor := WithMetrics(nil,
		WithExtractTagsFromCtx(extractTags1),
		WithExtractTagsFromCtx(extractTags2),
	)
	require.NotNil(t, interceptor)

	ctx := context.Background()
	req := "test-request"
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return "success", nil
	}

	resp, err := interceptor(ctx, req, info, handler)
	require.NoError(t, err)
	require.Equal(t, "success", resp)
}
