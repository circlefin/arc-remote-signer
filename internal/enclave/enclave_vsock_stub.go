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
	"errors"

	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awsproxy"
)

// buildAwsProxyVsock is defined in a build-tagged stub because its Linux
// counterpart calls awsproxy.WithVsockTransport, which is Linux-only and
// cannot be referenced from a non-Linux build — this file lets the package
// compile on non-Linux hosts (cross-compile sanity builds). It is never
// reached at runtime there because cfg.NitroEnclave.Enabled is false in
// dev/CI, so selectTransport picks TCP. It returns an explicit error rather
// than a no-op provider so any accidental reach fails loudly.
func buildAwsProxyVsock(_ *Config) (awsproxy.Provider, error) {
	return nil, errors.New("enclave: vsock transport requires Linux build")
}
