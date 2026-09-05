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

//go:build !prod

package enclave

import "github.com/circlefin/arc-remote-signer/internal/enclave/provider/awsproxy"

// Run starts the enclave service with the configured transport.
func Run(cfg *Config) error {
	return run(cfg, cfg.NitroEnclave.Enabled, buildAWSProxy)
}

type transportKind int

const (
	transportVsock transportKind = iota
	transportTCP
)

func selectTransport(cfg *Config) transportKind {
	if cfg.NitroEnclave.Enabled {
		return transportVsock
	}
	return transportTCP
}

func buildAWSProxy(cfg *Config) (awsproxy.Provider, error) {
	if selectTransport(cfg) == transportVsock {
		return buildAwsProxyVsock(cfg)
	}
	return awsproxy.New(cfg.Awsproxy, awsproxy.WithTCPTransport())
}
