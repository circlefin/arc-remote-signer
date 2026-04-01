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
	"net"
	"testing"

	pb "github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// TestLoggingWithLogger tests the loggingWithLogger function.
func TestLoggingWithLogger(t *testing.T) {
	const testRequestID = "test-request-id"
	interceptor := loggingWithLogger(getLogger())
	require.NotNil(t, interceptor)

	// Common variables
	port := 8080
	req := &pb.PublicKeyRequest{}
	info := &grpc.UnaryServerInfo{FullMethod: "TestMethod"}
	successHandler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return &pb.PublicKeyResponse{PublicKey: []byte("test-key")}, nil
	}

	testCases := map[string]struct {
		setupContext func() context.Context
		request      interface{}
		info         *grpc.UnaryServerInfo
		handler      func(ctx context.Context, req interface{}) (interface{}, error)
		expectError  bool
		expectNil    bool
		expectedType interface{}
	}{
		"successful request": {
			setupContext: func() context.Context {
				ctx := context.WithValue(context.Background(), requestIDContextKey{}, testRequestID)
				return peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: port}})
			},
			request:      req,
			info:         info,
			handler:      successHandler,
			expectError:  false,
			expectNil:    false,
			expectedType: &pb.PublicKeyResponse{},
		},
		"failed request": {
			setupContext: func() context.Context {
				ctx := context.WithValue(context.Background(), requestIDContextKey{}, testRequestID)
				return peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: port}})
			},
			request: req,
			info:    info,
			handler: func(_ context.Context, _ interface{}) (interface{}, error) {
				return nil, status.Error(codes.Internal, "internal server error")
			},
			expectError: true,
			expectNil:   true,
		},
		"request with metadata": {
			setupContext: func() context.Context {
				ctx := context.WithValue(context.Background(), requestIDContextKey{}, testRequestID)
				ctx = peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("172.16.0.1"), Port: port}})
				md := metadata.New(map[string]string{
					"user-agent": "test-client/1.0",
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			request:      req,
			info:         info,
			handler:      successHandler,
			expectError:  false,
			expectNil:    false,
			expectedType: &pb.PublicKeyResponse{},
		},
		"request with no metadata": {
			setupContext: func() context.Context {
				ctx := context.WithValue(context.Background(), requestIDContextKey{}, testRequestID)
				return peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}})
			},
			request:      req,
			info:         info,
			handler:      successHandler,
			expectError:  false,
			expectNil:    false,
			expectedType: &pb.PublicKeyResponse{},
		},
		"request with nil payload": {
			setupContext: func() context.Context {
				ctx := context.WithValue(context.Background(), requestIDContextKey{}, testRequestID)
				return peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: port}})
			},
			request:      nil,
			info:         info,
			handler:      successHandler,
			expectError:  false,
			expectNil:    false,
			expectedType: &pb.PublicKeyResponse{},
		},
		"request with unknown error": {
			setupContext: func() context.Context {
				ctx := context.WithValue(context.Background(), requestIDContextKey{}, testRequestID)
				return peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("9.9.9.9"), Port: port}})
			},
			request: req,
			info:    info,
			handler: func(_ context.Context, _ interface{}) (interface{}, error) {
				return nil, status.Error(codes.Unknown, "unknown error occurred")
			},
			expectError: true,
			expectNil:   true,
		},
		"request with ipv6 address": {
			setupContext: func() context.Context {
				ctx := context.WithValue(context.Background(), requestIDContextKey{}, testRequestID)
				return peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("::1"), Port: port}})
			},
			request:      req,
			info:         info,
			handler:      successHandler,
			expectError:  false,
			expectNil:    false,
			expectedType: &pb.PublicKeyResponse{},
		},
		"request with non-tcp address": {
			setupContext: func() context.Context {
				ctx := context.WithValue(context.Background(), requestIDContextKey{}, testRequestID)
				return peer.NewContext(ctx, &peer.Peer{Addr: &mockAddr{addr: "unix:/tmp/test.sock"}})
			},
			request:      req,
			info:         info,
			handler:      successHandler,
			expectError:  false,
			expectNil:    false,
			expectedType: &pb.PublicKeyResponse{},
		},
		"request with no peer context": {
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), requestIDContextKey{}, testRequestID)
			},
			request:      req,
			info:         info,
			handler:      successHandler,
			expectError:  false,
			expectNil:    false,
			expectedType: &pb.PublicKeyResponse{},
		},
		"request without request id in context": {
			setupContext: func() context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2"), Port: port}})
			},
			request:      req,
			info:         info,
			handler:      successHandler,
			expectError:  false,
			expectNil:    false,
			expectedType: &pb.PublicKeyResponse{},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := tc.setupContext()
			resp, err := interceptor(ctx, tc.request, tc.info, tc.handler)

			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tc.expectNil {
				require.Nil(t, resp)
			} else {
				require.NotNil(t, resp)
				if tc.expectedType != nil {
					require.IsType(t, tc.expectedType, resp)
				}
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	testCases := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{
			name:     "no peer context",
			ctx:      context.Background(),
			expected: "unknown",
		},
		{
			name:     "tcp address",
			ctx:      peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}}),
			expected: "192.168.1.1",
		},
		{
			name:     "ipv6 tcp address",
			ctx:      peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("::1"), Port: 8080}}),
			expected: "::1",
		},
		{
			name:     "string address with port",
			ctx:      peer.NewContext(context.Background(), &peer.Peer{Addr: &mockAddr{addr: "10.0.0.1:12345"}}),
			expected: "10.0.0.1",
		},
		{
			name:     "string address without port",
			ctx:      peer.NewContext(context.Background(), &peer.Peer{Addr: &mockAddr{addr: "172.16.0.1"}}),
			expected: "172.16.0.1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getClientIP(tc.ctx)
			require.Equal(t, tc.expected, result)
		})
	}
}

// mockAddr implements net.Addr for testing.
type mockAddr struct {
	addr string
}

func (m *mockAddr) Network() string { return "tcp" }
func (m *mockAddr) String() string  { return m.addr }
