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

package vsockproxy

import (
	"fmt"
	"os"
	"path/filepath"
)

// readyFileEnv names the env var the launcher (docker/run.sh) sets to a
// readiness sentinel path. vsockproxy creates the file only after every
// listener is bound — which happens synchronously in New — so the parent
// can gate enclave startup on the proxy actually listening instead of
// probing the kernel (vsock listeners are not enumerable from the host via
// /proc or the tools shipped in the image). An empty/unset value disables
// the signal, so compose, smoke, and local runs are unaffected.
const readyFileEnv = "VSOCKPROXY_READY_FILE"

// createReadyTemp creates a temp file in dir that signalReady renames into
// place. It is a package var so tests can exercise the close-failure branch,
// which is otherwise impossible to trigger deterministically for a freshly
// created empty file.
var createReadyTemp = func(dir string) (*os.File, error) {
	return os.CreateTemp(dir, "vsockproxy.ready-*")
}

// signalReady publishes the readiness sentinel when readyFileEnv is set.
// It MUST be called only after New returns successfully, i.e. once all
// listeners are bound. A failure is returned so the caller aborts rather
// than leaving the parent waiting on a file that never appears.
//
// The sentinel is written to a temp file in the same directory and renamed
// into place only after Close succeeds. Rename is atomic within a
// filesystem, so docker/run.sh can never observe the sentinel before it is
// fully written — a failure at any step leaves no sentinel, so the parent
// cannot false-ready for a proxy that did not come up cleanly.
func signalReady() error {
	path := os.Getenv(readyFileEnv)
	if path == "" {
		return nil
	}
	f, err := createReadyTemp(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("vsockproxy: write readiness file %q: %w", path, err)
	}
	tmp := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("vsockproxy: close readiness file %q: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("vsockproxy: publish readiness file %q: %w", path, err)
	}
	return nil
}
