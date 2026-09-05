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

// AWSServiceNames is the ordered list of AWS services the enclave-side and
// host-side proxies must agree on. Indices determine the port offset from
// each side's BasePort, so adding or reordering entries here is the single
// edit point — wrappers derive their per-service config from this slice.
//
// Order mirrors gateway-tee-signer's hardcoded ["KMS", "SecretsManager",
// "STS"]. Entries beyond the first are reserved for later subtasks and are
// inert until they have AWS SDK consumers in the enclave.
//
// DO NOT mutate this slice at runtime. Callers (awsproxy on the enclave,
// vsockproxy on the host) coordinate port assignments by iterating this
// list and would observe inconsistent ports if append/reorder happened
// after either wrapper has been constructed.
var AWSServiceNames = []string{"kms"}
