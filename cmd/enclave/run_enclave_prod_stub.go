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

//go:build prod && (!linux || !cgo)

package main

import (
	"errors"

	"github.com/circlefin/arc-remote-signer/internal/enclave"
)

var errProductionEnclaveUnsupported = errors.New("production enclave requires Linux and cgo")

func runConfiguredEnclave(*enclave.Config) error {
	return errProductionEnclaveUnsupported
}
