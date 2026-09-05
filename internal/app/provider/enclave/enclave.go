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
	"strings"

	"github.com/circlefin/arc-remote-signer/internal/common/grpc/client"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"google.golang.org/grpc"
)

// New creates a new enclave provider.
func New(pc *ProviderConfig) (pb.EnclaveServiceClient, *grpc.ClientConn, error) {
	var extraDialOptions []grpc.DialOption
	if pc != nil && pc.NitroEnclave != nil && pc.NitroEnclave.Enabled {
		if pc.NitroEnclave.CID == 0 || pc.NitroEnclave.Port == 0 {
			return nil, nil, fmt.Errorf("nitro enclave mode requires a valid CID and port")
		}
		extraDialOptions = append(extraDialOptions, grpc.WithContextDialer(NewVsockDialer(pc.NitroEnclave.CID, pc.NitroEnclave.Port)))
	}
	return newClient(pc, extraDialOptions...)
}

// NewNitro creates an enclave client that always uses VSOCK.
func NewNitro(pc *ProviderConfig) (pb.EnclaveServiceClient, *grpc.ClientConn, error) {
	if pc == nil || pc.NitroEnclave == nil || pc.NitroEnclave.CID == 0 || pc.NitroEnclave.Port == 0 {
		return nil, nil, fmt.Errorf("nitro enclave mode requires a valid CID and port")
	}
	return newClient(
		pc,
		grpc.WithContextDialer(NewVsockDialer(pc.NitroEnclave.CID, pc.NitroEnclave.Port)),
	)
}

func newClient(pc *ProviderConfig, extraDialOptions ...grpc.DialOption) (pb.EnclaveServiceClient, *grpc.ClientConn, error) {
	if pc == nil {
		return nil, nil, fmt.Errorf("provider config is nil")
	}
	if pc.Client == nil {
		return nil, nil, fmt.Errorf("provider client config is nil")
	}

	clientConfig := pinInitializeTransportAttempts(*pc.Client)
	conn, err := client.NewInsecureClientConn(pc.Client.BaseURL, clientConfig, extraDialOptions...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create enclave client connection: %w", err)
	}

	return pb.NewEnclaveServiceClient(conn), conn, nil
}

func pinInitializeTransportAttempts(cfg client.Config) client.Config {
	methods := make(map[string]client.MethodConfig, len(cfg.Methods)+1)
	for method, methodConfig := range cfg.Methods {
		if slash := strings.LastIndex(method, "/"); slash >= 0 {
			if strings.EqualFold(method[slash+1:], "Initialize") {
				methodConfig.MaxAttempts = 1
			}
		} else if strings.EqualFold(method, "Initialize") {
			methodConfig.MaxAttempts = 1
		}
		methods[method] = methodConfig
	}
	initializeConfig, ok := methods["initialize"]
	if !ok {
		initializeConfig.TimeoutMS = defaultStartupTimeoutMS
	}
	initializeConfig.MaxAttempts = 1
	methods["initialize"] = initializeConfig
	cfg.Methods = methods
	return cfg
}
