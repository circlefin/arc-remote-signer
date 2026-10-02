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

//go:build linux && prod

package vsockproxy

func applyBuildPolicy(cfg *Config) {
	// The production build sends AWS requests to AWS KMS endpoints through VSOCK.
	cfg.Vsockproxy.BasePort = DefaultBasePort
	cfg.Provider.Enclave.NitroEnclave.Enabled = true
	cfg.Provider.AWSKMS.Localstack.Enabled = false
}

func runtimeTransportOption(*Config) Option {
	return WithVsockTransport()
}
