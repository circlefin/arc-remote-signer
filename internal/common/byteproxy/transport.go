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

package byteproxy

// TransportKind identifies which transport a proxy wrapper has selected.
// The enclave-side awsproxy and the host-side vsockproxy wrappers share
// this enum so the two sides of the bridge name transports identically.
// The zero value is TransportVsock, the production default; the wrapper
// packages (awsproxy, vsockproxy) expose a WithTCPTransport option to select
// TCP for dev/CI. A transport option installs the matching listen/dial
// unconditionally, so when a caller passes more than one transport option
// the last one wins.
type TransportKind int

const (
	// TransportVsock selects the vsock transport (Linux only). It is the
	// zero value, so a caller that passes no transport option gets vsock.
	TransportVsock TransportKind = iota
	// TransportTCP selects the TCP transport (dev/CI).
	TransportTCP
)
