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
	"errors"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRecoveryWithLogger(t *testing.T) {
	type contextKey string
	const testContextKey contextKey = "test-key"
	testCases := []struct {
		name           string
		req            interface{}
		handler        func(ctx context.Context, req interface{}) (interface{}, error)
		expectedResp   interface{}
		expectedError  error
		expectPanic    bool
		panicValue     interface{}
		checkGRPCError bool
		expectCode     codes.Code
	}{
		{
			name:         "Normal Execution",
			req:          "test request",
			expectedResp: "test response",
			handler: func(_ context.Context, _ interface{}) (interface{}, error) {
				return "test response", nil
			},
		},
		{
			name:          "Handler Error",
			req:           "test request",
			expectedError: errors.New("handler error"),
			handler: func(_ context.Context, _ interface{}) (interface{}, error) {
				return nil, errors.New("handler error")
			},
		},
		{
			name:        "Panic Recovery with String",
			req:         "test request",
			expectPanic: true,
			panicValue:  "test panic",
			handler: func(_ context.Context, _ interface{}) (interface{}, error) {
				panic("test panic")
			},
			checkGRPCError: true,
			expectCode:     codes.Internal,
		},
		{
			name:        "Panic Recovery with Nil",
			req:         "test request",
			expectPanic: true,
			panicValue:  nil,
			handler: func(_ context.Context, _ interface{}) (interface{}, error) {
				panic(nil)
			},
			checkGRPCError: true,
			expectCode:     codes.Internal,
		},
		{
			name:        "Panic Recovery with Struct",
			req:         "test request",
			expectPanic: true,
			panicValue: struct {
				Message string
				Code    int
			}{
				Message: "structured panic",
				Code:    500,
			},
			handler: func(_ context.Context, _ interface{}) (interface{}, error) {
				panic(struct {
					Message string
					Code    int
				}{
					Message: "structured panic",
					Code:    500,
				})
			},
			checkGRPCError: true,
			expectCode:     codes.Internal,
		},
		{
			name:        "Panic Recovery with Error",
			req:         "test request",
			expectPanic: true,
			panicValue:  errors.New("panic error"),
			handler: func(_ context.Context, _ interface{}) (interface{}, error) {
				panic(errors.New("panic error"))
			},
			checkGRPCError: true,
			expectCode:     codes.Internal,
		},
		{
			name:        "Broken Pipe Panic",
			req:         "test request",
			expectPanic: true,
			panicValue: &net.OpError{
				Op:  "write",
				Net: "tcp",
				Err: &os.SyscallError{
					Syscall: "write",
					Err:     errors.New("broken pipe"),
				},
			},
			handler: func(_ context.Context, _ interface{}) (interface{}, error) {
				panic(&net.OpError{
					Op:  "write",
					Net: "tcp",
					Err: &os.SyscallError{
						Syscall: "write",
						Err:     errors.New("broken pipe"),
					},
				})
			},
			checkGRPCError: true,
			expectCode:     codes.Unavailable,
			// Note: In real scenarios, when broken pipe occurs, the client connection
			// is already closed, so the error response cannot be sent to the client.
			// This test only verifies the middleware logic, not the actual network behavior.
		},
		{
			name:        "Connection Reset Panic",
			req:         "test request",
			expectPanic: true,
			panicValue: &net.OpError{
				Op:  "write",
				Net: "tcp",
				Err: &os.SyscallError{
					Syscall: "write",
					Err:     errors.New("connection reset by peer"),
				},
			},
			handler: func(_ context.Context, _ interface{}) (interface{}, error) {
				panic(&net.OpError{
					Op:  "write",
					Net: "tcp",
					Err: &os.SyscallError{
						Syscall: "write",
						Err:     errors.New("connection reset by peer"),
					},
				})
			},
			checkGRPCError: true,
			expectCode:     codes.Unavailable,
			// Note: Similar to broken pipe, connection reset means the client
			// connection is already closed, so the error response cannot be sent.
			// This test only verifies the middleware logic.
		},
		{
			name:         "Context Preservation",
			req:          "test request",
			expectedResp: "success",
			handler: func(ctx context.Context, _ interface{}) (interface{}, error) {
				value := ctx.Value(testContextKey)
				if value != "test-value" {
					return nil, errors.New("context value not preserved")
				}
				return "success", nil
			},
		},
		{
			name:         "Request Preservation",
			req:          map[string]string{"key": "value"},
			expectedResp: "request preserved",
			handler: func(_ context.Context, req interface{}) (interface{}, error) {
				if reqMap, ok := req.(map[string]string); ok {
					if reqMap["key"] == "value" {
						return "request preserved", nil
					}
				}
				return nil, errors.New("request not preserved")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			ctx := context.Background()
			if tc.name == "Context Preservation" {
				ctx = context.WithValue(ctx, testContextKey, "test-value")
			}

			info := &grpc.UnaryServerInfo{
				FullMethod: "/test.Service/TestMethod",
			}

			// Create the interceptor
			interceptor := recoveryWithLogger(getLogger())

			// Execute
			resp, err := interceptor(ctx, tc.req, info, tc.handler)

			// Assert
			if tc.expectPanic {
				require.Error(t, err)
				assert.Nil(t, resp)

				if tc.checkGRPCError {
					// Check that the error is a gRPC status error
					st, ok := status.FromError(err)
					require.True(t, ok)
					assert.Equal(t, tc.expectCode, st.Code())

					// Check error message based on panic type
					if tc.expectCode == codes.Unavailable {
						assert.Contains(t, st.Message(), "connection closed")
					} else {
						assert.Contains(t, st.Message(), "something went wrong")

						// Check panic value in error message if it's a string
						if panicStr, ok := tc.panicValue.(string); ok {
							assert.Contains(t, st.Message(), panicStr)
						}
					}
				}
			} else if tc.expectedError != nil {
				require.Error(t, err)
				assert.Nil(t, resp)
				assert.Equal(t, tc.expectedError, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedResp, resp)
			}
		})
	}
}
