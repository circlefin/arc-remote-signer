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

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestRequestID(t *testing.T) {
	tests := []struct {
		name           string
		setupContext   func() context.Context
		expectedResult func(t *testing.T, ctx context.Context, reqID string)
	}{
		{
			name: "should use request ID from metadata when present",
			setupContext: func() context.Context {
				reqID := "test-request-id-123"
				md := metadata.New(map[string]string{
					requestIDHeaderKey: reqID,
				})
				return metadata.NewIncomingContext(context.Background(), md)
			},
			expectedResult: func(t *testing.T, ctx context.Context, reqID string) {
				assert.Equal(t, "test-request-id-123", reqID)
				assert.Equal(t, reqID, ctx.Value(requestIDContextKey{}))
			},
		},
		{
			name: "should generate new UUID when no request ID in metadata",
			setupContext: func() context.Context {
				return context.Background()
			},
			expectedResult: func(t *testing.T, ctx context.Context, reqID string) {
				// Should be a valid UUID
				_, err := uuid.Parse(reqID)
				assert.NoError(t, err)
				assert.Equal(t, reqID, ctx.Value(requestIDContextKey{}))
			},
		},
		{
			name: "should use trace ID when span is valid and no request ID in metadata",
			setupContext: func() context.Context {
				tracer := noop.NewTracerProvider().Tracer("test")
				ctx, span := tracer.Start(context.Background(), "test-span")
				defer span.End()
				return ctx
			},
			expectedResult: func(t *testing.T, ctx context.Context, reqID string) {
				// Should use trace ID from span if it's not zero, otherwise fallback to UUID
				span := trace.SpanFromContext(ctx)
				traceID := span.SpanContext().TraceID().String()
				if traceID == "00000000000000000000000000000000" {
					// If trace ID is zero, should fallback to UUID
					_, err := uuid.Parse(reqID)
					assert.NoError(t, err)
				} else {
					assert.Equal(t, traceID, reqID)
				}
				assert.Equal(t, reqID, ctx.Value(requestIDContextKey{}))
			},
		},
		{
			name: "should prioritize metadata request ID over trace ID",
			setupContext: func() context.Context {
				tracer := noop.NewTracerProvider().Tracer("test")
				ctx, span := tracer.Start(context.Background(), "test-span")
				defer span.End()

				reqID := "metadata-request-id-456"
				md := metadata.New(map[string]string{
					requestIDHeaderKey: reqID,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedResult: func(t *testing.T, ctx context.Context, reqID string) {
				assert.Equal(t, "metadata-request-id-456", reqID)
				assert.Equal(t, reqID, ctx.Value(requestIDContextKey{}))
			},
		},
		{
			name: "should handle empty metadata gracefully",
			setupContext: func() context.Context {
				md := metadata.New(nil)
				return metadata.NewIncomingContext(context.Background(), md)
			},
			expectedResult: func(t *testing.T, ctx context.Context, reqID string) {
				// Should be a valid UUID
				_, err := uuid.Parse(reqID)
				assert.NoError(t, err)
				assert.Equal(t, reqID, ctx.Value(requestIDContextKey{}))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			ctx := tt.setupContext()
			interceptor := requestID()

			// Mock request and handler
			req := "test-request"
			var capturedCtx context.Context
			var capturedReqID string

			handler := func(ctx context.Context, _ interface{}) (interface{}, error) {
				capturedCtx = ctx
				capturedReqID = ctx.Value(requestIDContextKey{}).(string)
				return "test-response", nil
			}

			// Execute
			resp, err := interceptor(ctx, req, &grpc.UnaryServerInfo{}, handler)

			// Assertions
			require.NoError(t, err)
			assert.Equal(t, "test-response", resp)
			assert.NotNil(t, capturedCtx)
			assert.NotEmpty(t, capturedReqID)

			// Check that request ID is set in outgoing metadata
			outgoingMD, ok := metadata.FromOutgoingContext(capturedCtx)
			require.True(t, ok)
			requestIDs := outgoingMD.Get(requestIDHeaderKey)
			require.Len(t, requestIDs, 1)
			assert.Equal(t, capturedReqID, requestIDs[0])

			// Run custom assertions
			tt.expectedResult(t, capturedCtx, capturedReqID)
		})
	}
}

func TestRequestID_HandlerError(t *testing.T) {
	// Test that interceptor properly handles handler errors
	ctx := context.Background()
	interceptor := requestID()

	expectedErr := assert.AnError
	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return nil, expectedErr
	}

	resp, err := interceptor(ctx, "test-request", &grpc.UnaryServerInfo{}, handler)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, resp)
}

func TestRequestID_ContextValueRetrieval(t *testing.T) {
	// Test that request ID can be retrieved from context after interceptor
	ctx := context.Background()
	interceptor := requestID()

	var capturedReqID string
	handler := func(ctx context.Context, _ interface{}) (interface{}, error) {
		capturedReqID = ctx.Value(requestIDContextKey{}).(string)
		return nil, nil
	}

	_, err := interceptor(ctx, "test-request", &grpc.UnaryServerInfo{}, handler)
	require.NoError(t, err)

	// Verify request ID is a valid UUID
	_, err = uuid.Parse(capturedReqID)
	assert.NoError(t, err)
}

func TestRequestID_MetadataPreservation(t *testing.T) {
	// Test that existing metadata is preserved
	originalMD := metadata.New(map[string]string{
		"user-agent":    "test-client",
		"authorization": "Bearer token123",
	})
	ctx := metadata.NewIncomingContext(context.Background(), originalMD)

	interceptor := requestID()

	var capturedCtx context.Context
	handler := func(ctx context.Context, _ interface{}) (interface{}, error) {
		capturedCtx = ctx
		return nil, nil
	}

	_, err := interceptor(ctx, "test-request", &grpc.UnaryServerInfo{}, handler)
	require.NoError(t, err)

	// Check that outgoing metadata contains both original and new request ID
	outgoingMD, ok := metadata.FromOutgoingContext(capturedCtx)
	require.True(t, ok)

	// Original metadata should be preserved
	assert.Equal(t, "test-client", outgoingMD.Get("user-agent")[0])
	assert.Equal(t, "Bearer token123", outgoingMD.Get("authorization")[0])

	// Request ID should be added
	requestIDs := outgoingMD.Get(requestIDHeaderKey)
	require.Len(t, requestIDs, 1)
	assert.NotEmpty(t, requestIDs[0])
}

func TestRequestID_WithRequestID(t *testing.T) {
	// Test the exported WithRequestID function
	interceptor := WithRequestID()
	assert.NotNil(t, interceptor)

	ctx := context.Background()
	var capturedReqID string
	handler := func(ctx context.Context, _ interface{}) (interface{}, error) {
		capturedReqID = ctx.Value(requestIDContextKey{}).(string)
		return nil, nil
	}

	_, err := interceptor(ctx, "test-request", &grpc.UnaryServerInfo{}, handler)
	require.NoError(t, err)

	// Verify request ID is set
	assert.NotEmpty(t, capturedReqID)
	_, err = uuid.Parse(capturedReqID)
	assert.NoError(t, err)
}
