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

//go:generate mockgen -destination=enclave_mock.go -package=enclave github.com/circlefin/arc-remote-signer/proto/pb EnclaveServiceClient

// Package enclave provides a provider for the enclave service.
package enclave

import (
	"fmt"

	"github.com/circlefin/arc-remote-signer/internal/common/grpc/client"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"google.golang.org/grpc"
)

// New creates a new enclave provider.
func New(pc *ProviderConfig) (pb.EnclaveServiceClient, *grpc.ClientConn, error) {
	if pc == nil {
		return nil, nil, fmt.Errorf("provider config is nil")
	}
	if pc.Client == nil {
		return nil, nil, fmt.Errorf("provider client config is nil")
	}

	nitroEnabled := pc.NitroEnclave != nil && pc.NitroEnclave.Enabled
	if nitroEnabled && (pc.NitroEnclave.CID <= 0 || pc.NitroEnclave.Port == 0) {
		return nil, nil, fmt.Errorf("nitro enclave is enabled but cid or port is invalid")
	}

	var extraDialOptions []grpc.DialOption
	if nitroEnabled {
		extraDialOptions = append(extraDialOptions, grpc.WithContextDialer(NewVsockDialer(pc.NitroEnclave.CID, pc.NitroEnclave.Port)))
	}

	conn, err := client.NewInsecureClientConn(pc.Client.BaseURL, *pc.Client, extraDialOptions...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create enclave client connection: %w", err)
	}

	return pb.NewEnclaveServiceClient(conn), conn, nil
}
