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

//go:build !linux

package enclave

import (
	"context"
	"fmt"
	"net"
)

// NewVsockDialer creates a gRPC dialer function for VSOCK.
// This is a stub for non-Linux platforms.
func NewVsockDialer(cid, port uint32) func(ctx context.Context, _ string) (net.Conn, error) {
	return func(_ context.Context, _ string) (net.Conn, error) {
		panic(fmt.Sprintf("VSOCK transport is only supported on Linux (attempted CID=%d, Port=%d)", cid, port))
	}
}
