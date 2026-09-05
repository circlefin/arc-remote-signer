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
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	grpcRetry "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
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
	if cfg.RequestTimeoutMS > 0 || len(cfg.Methods) > 0 {
		unaryInterceptors = append(unaryInterceptors, unaryMethodTimeoutInterceptor(cfg))
	}
	if len(cfg.Methods) > 0 {
		unaryInterceptors = append(unaryInterceptors, unaryMethodRetryInterceptor(cfg))
	}
	if maxAttempts > 0 || hasMethodMaxAttempts(cfg.Methods) {
		unaryInterceptors = append(unaryInterceptors, grpcRetry.UnaryClientInterceptor(
			grpcRetry.WithMax(maxAttempts),
			grpcRetry.WithCodes(retryCodes...),
		))
	}
	unaryInterceptors = append(unaryInterceptors, extraInterceptors...)

	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(unaryInterceptors...),
	}
}

// unaryMethodTimeoutInterceptor applies the configured per-method timeout or
// the global request timeout to each unary RPC.
func unaryMethodTimeoutInterceptor(cfg Config) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		timeout := resolveMethodTimeout(cfg, method)
		if timeout <= 0 {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func unaryMethodRetryInterceptor(cfg Config) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		if methodCfg, ok := lookupMethodConfig(cfg, method); ok && methodCfg.MaxAttempts > 0 {
			opts = append(opts, grpcRetry.WithMax(methodCfg.MaxAttempts))
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func hasMethodMaxAttempts(methods map[string]MethodConfig) bool {
	for _, methodCfg := range methods {
		if methodCfg.MaxAttempts > 0 {
			return true
		}
	}
	return false
}

func resolveMethodTimeout(cfg Config, fullMethod string) time.Duration {
	if methodCfg, ok := lookupMethodConfig(cfg, fullMethod); ok {
		if methodCfg.TimeoutMS < 0 {
			return 0
		}
		if methodCfg.TimeoutMS > 0 {
			return time.Duration(methodCfg.TimeoutMS) * time.Millisecond
		}
	}
	if cfg.RequestTimeoutMS > 0 {
		return time.Duration(cfg.RequestTimeoutMS) * time.Millisecond
	}
	return 0
}

func lookupMethodConfig(cfg Config, fullMethod string) (MethodConfig, bool) {
	if methodCfg, ok := cfg.Methods[fullMethod]; ok {
		return methodCfg, true
	}
	if methodCfg, ok := cfg.Methods[strings.ToLower(fullMethod)]; ok {
		return methodCfg, true
	}
	if idx := strings.LastIndex(fullMethod, "/"); idx >= 0 {
		shortMethod := fullMethod[idx+1:]
		if methodCfg, ok := cfg.Methods[shortMethod]; ok {
			return methodCfg, true
		}
		methodCfg, ok := cfg.Methods[strings.ToLower(shortMethod)]
		return methodCfg, ok
	}
	return MethodConfig{}, false
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
