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

//go:build linux

package enclave

import (
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awsproxy"
)

// buildAwsProxyVsock returns the production vsock-transport awsproxy.
// Linux-only because awsproxy.WithVsockTransport is Linux-only.
func buildAwsProxyVsock(cfg *Config) (awsproxy.Provider, error) {
	return awsproxy.New(cfg.Awsproxy, awsproxy.WithVsockTransport())
}
