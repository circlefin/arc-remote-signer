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
	"time"

	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// loggingWithLogger returns a gRPC unary interceptor that logs each request and response,
// including client IP, method, user agent, request ID, status code, and latency.
func loggingWithLogger(logger *logging.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		start := time.Now()

		// Extract metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.New(nil)
		}

		fields := logging.Entries{
			"clientIP":  getClientIP(ctx),
			"method":    info.FullMethod,
			"userAgent": "unknown",
			"requestID": "unknown",
		}

		// Extract request ID from context when available.
		if requestID, ok := ctx.Value(requestIDContextKey{}).(string); ok {
			fields["requestID"] = requestID
		}

		// Extract user agent from metadata if available
		if userAgents := md.Get("user-agent"); len(userAgents) > 0 {
			fields["userAgent"] = userAgents[0]
		}

		// Set logging context
		ctx = logging.SetInContext(ctx, logging.NewTags())

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

		// Log response
		postFields := logging.Entries{
			"status":                      statusCode.String(),
			logging.RequestTimeLoggingKey: latency.Milliseconds(),
		}

		// Merge fields
		for k, v := range postFields {
			fields[k] = v
		}

		// Log based on success/failure
		if err != nil {
			fields["error"] = err.Error()
			logger.Error(ctx, "gRPC request failed", fields)
		} else {
			logger.Info(ctx, "gRPC request completed", fields)
		}

		return resp, err
	}
}

// getClientIP extracts the client IP address from the gRPC context.
func getClientIP(ctx context.Context) string {
	// Try to get peer info from gRPC context
	if p, ok := peer.FromContext(ctx); ok {
		if addr, ok := p.Addr.(*net.TCPAddr); ok {
			return addr.IP.String()
		}
		// Fallback for non-TCP connections.
		// Use net.SplitHostPort to correctly handle both IPv4 and IPv6 addresses.
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err == nil {
			return host
		}
		// If SplitHostPort fails, it might be an address without a port.
		return p.Addr.String()
	}
	return "unknown"
}
