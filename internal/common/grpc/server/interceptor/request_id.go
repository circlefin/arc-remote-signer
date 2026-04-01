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

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// httpRequestIDKey is the OpenTelemetry attribute key for the HTTP request ID.
const httpRequestIDKey = attribute.Key("http.request_id")

// requestIDContextKey is the key for the request ID in the context.
type requestIDContextKey struct{}

// requestIDHeaderKey is the key for the request ID in the header.
const requestIDHeaderKey = "x-request-id"

// requestID returns a gRPC unary interceptor that ensures each request has a request ID
// in its context. It reads an existing ID from incoming metadata, falls back to the
// trace ID if available, or generates a new UUID otherwise.
func requestID() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		reqIDStr := uuid.New().String()
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.New(nil)
		}

		requestID := md.Get(requestIDHeaderKey)
		if len(requestID) != 0 {
			reqIDStr = requestID[0]
		} else {
			span := trace.SpanFromContext(ctx)
			if span.SpanContext().IsValid() {
				reqIDStr = span.SpanContext().TraceID().String()
			}
		}
		ctx = context.WithValue(ctx, requestIDContextKey{}, reqIDStr)
		// Set request ID in response metadata for gRPC
		outgoingMD := md.Copy()
		outgoingMD.Set(requestIDHeaderKey, reqIDStr)
		ctx = metadata.NewOutgoingContext(ctx, outgoingMD)
		trace.SpanFromContext(ctx).SetAttributes(
			httpRequestIDKey.String(reqIDStr),
		)
		return handler(ctx, req)
	}
}
