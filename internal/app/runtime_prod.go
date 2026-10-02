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

//go:build prod

package app

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsSdkConfig "github.com/aws/aws-sdk-go-v2/config"
	enclaveProvider "github.com/circlefin/arc-remote-signer/internal/app/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/app/provider/secrets"
	"github.com/circlefin/arc-remote-signer/internal/common/config"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"google.golang.org/grpc"
)

const (
	// The production host uses a fixed CID and port. This rule prevents
	// configuration from selecting a local VSOCK peer.
	productionEnclaveCID  uint32 = 16
	productionEnclavePort uint32 = 10350
)

func applyBuildPolicy(cfg *Config) {
	// The environment value identifies the deployment only. It must not select runtime behavior.
	if cfg.Env != config.Stg {
		cfg.Env = config.Prod
	}
	cfg.Provider.Enclave.NitroEnclave.Enabled = true
	cfg.Provider.Enclave.NitroEnclave.CID = productionEnclaveCID
	cfg.Provider.Enclave.NitroEnclave.Port = productionEnclavePort
	cfg.Provider.Enclave.Client.BaseURL = fmt.Sprintf("localhost:%d", productionEnclavePort)
	cfg.Provider.Secrets.Localstack.Enabled = false
	cfg.Provider.AWSKMS.Localstack.Enabled = false
}

// NewConfig returns production configuration.
func NewConfig() *Config {
	cfg := newConfig(
		config.NewBaseConfig(),
		&secrets.Config{Localstack: &secrets.LocalstackConfig{}},
		&AWSKMSConfig{Localstack: &AWSKMSLocalstackConfig{}},
	)
	applyBuildPolicy(cfg)
	return cfg
}

func newRuntimeEnclave(cfg *enclaveProvider.ProviderConfig) (pb.EnclaveServiceClient, *grpc.ClientConn, error) {
	return enclaveProvider.NewNitro(cfg)
}

func loadRuntimeAWSConfig(ctx context.Context, _ *Config, logger *logging.Logger) (aws.Config, error) {
	logger.Info(ctx, "The signer uses the standard AWS configuration.", nil)
	cfg, err := awsSdkConfig.LoadDefaultConfig(ctx)
	if err != nil {
		return aws.Config{}, err
	}
	cfg.BaseEndpoint = nil
	cfg.ConfigSources = append([]interface{}{productionEndpointPolicy{}}, cfg.ConfigSources...)
	return cfg, nil
}

// productionEndpointPolicy disables SDK endpoint settings.
type productionEndpointPolicy struct{}

func (productionEndpointPolicy) GetIgnoreConfiguredEndpoints(context.Context) (bool, bool, error) {
	return true, true, nil
}
