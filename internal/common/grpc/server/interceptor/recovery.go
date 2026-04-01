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
	"runtime/debug"
	"strings"

	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// recoveryWithLogger returns a gRPC unary interceptor that recovers from panics,
// logs the error, and returns an internal server error to the caller.
// Broken pipe and connection reset errors are logged at info level and suppressed.
func recoveryWithLogger(logger *logging.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				var brokenPipe bool
				if ne, ok := r.(*net.OpError); ok {
					var se *os.SyscallError
					if errors.As(ne, &se) {
						seStr := strings.ToLower(se.Error())
						if strings.Contains(seStr, "broken pipe") ||
							strings.Contains(seStr, "connection reset by peer") {
							brokenPipe = true
						}
					}
				}

				if brokenPipe {
					if err, ok := r.(error); ok {
						logger.InfoErr(ctx, "[Recovery from panic]", err, nil)
					} else {
						logger.Info(ctx, "[Recovery from panic]", logging.Entries{"r": r})
					}
				} else if err, ok := r.(error); ok {
					logger.ErrorErr(ctx, "[Recovery from panic]", err, nil)
				} else {
					logger.Error(ctx, "[Recovery from panic]", logging.Entries{"stack": string(debug.Stack()), "r": r})
				}

				if brokenPipe {
					if e, ok := r.(error); ok {
						err = status.Errorf(codes.Unavailable, "connection closed: %v", e)
					} else {
						err = status.Error(codes.Unavailable, "connection closed")
					}
				} else {
					err = status.Errorf(codes.Internal, "something went wrong: %v", r)
				}
			}
		}()
		return handler(ctx, req)
	}
}
