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

// Package client provides shared helpers for outbound gRPC clients.
package client

import (
	"fmt"
	"net"
	"time"

	grpcRetry "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	grpcTimeout "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/timeout"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
)

// InsecureDialOptions builds standard insecure gRPC client dial options.
func InsecureDialOptions(cfg Config, extraInterceptors ...grpc.UnaryClientInterceptor) []grpc.DialOption {
	var (
		maxAttempts       uint
		retryCodes        []codes.Code
		unaryInterceptors []grpc.UnaryClientInterceptor
	)
	if cfg.Retry != nil {
		maxAttempts = cfg.Retry.MaxAttempts
		retryCodes = cfg.Retry.RetryCodes
	}
	if len(retryCodes) == 0 {
		retryCodes = defaultRetryCodes
	}
	if maxAttempts > 0 {
		unaryInterceptors = append(unaryInterceptors, grpcRetry.UnaryClientInterceptor(
			grpcRetry.WithMax(maxAttempts),
			grpcRetry.WithCodes(retryCodes...),
		))
	}
	if cfg.RequestTimeoutMS > 0 {
		unaryInterceptors = append([]grpc.UnaryClientInterceptor{
			grpcTimeout.UnaryClientInterceptor(time.Duration(cfg.RequestTimeoutMS) * time.Millisecond),
		}, unaryInterceptors...)
	}
	unaryInterceptors = append(unaryInterceptors, extraInterceptors...)

	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(unaryInterceptors...),
	}
}

// NewInsecureClientConn creates an insecure grpc client connection from config.
func NewInsecureClientConn(rawTarget string, cfg Config, extraDialOptions ...grpc.DialOption) (*grpc.ClientConn, error) {
	if _, _, err := net.SplitHostPort(rawTarget); err != nil {
		return nil, fmt.Errorf("invalid grpc target %q: expected host:port", rawTarget)
	}

	dialOpts := InsecureDialOptions(cfg)
	dialOpts = append(dialOpts, extraDialOptions...)
	return grpc.NewClient(rawTarget, dialOpts...)
}
