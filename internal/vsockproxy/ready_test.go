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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignalReady(t *testing.T) {
	t.Run("unset env is a no-op", func(t *testing.T) {
		t.Setenv(readyFileEnv, "")
		require.NoError(t, signalReady())
	})

	t.Run("creates sentinel file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "vsockproxy.ready")
		t.Setenv(readyFileEnv, path)

		require.NoError(t, signalReady())
		require.FileExists(t, path)
	})

	t.Run("unwritable path errors", func(t *testing.T) {
		// A path whose parent directory does not exist cannot be created;
		// the error must propagate so the launcher does not block on a
		// sentinel that will never appear.
		path := filepath.Join(t.TempDir(), "no-such-dir", "vsockproxy.ready")
		t.Setenv(readyFileEnv, path)

		err := signalReady()
		require.ErrorContains(t, err, path)
	})

	t.Run("close failure leaves no sentinel and wraps error", func(t *testing.T) {
		// Force the close-failure branch via the createReadyTemp seam: the
		// returned file is already closed, so signalReady's Close errors
		// before it can rename the temp into place. The sentinel must never
		// appear and the leftover temp must be removed.
		dir := t.TempDir()
		path := filepath.Join(dir, "vsockproxy.ready")
		orig := createReadyTemp
		t.Cleanup(func() { createReadyTemp = orig })
		createReadyTemp = func(d string) (*os.File, error) {
			f, err := os.CreateTemp(d, "vsockproxy.ready-*")
			require.NoError(t, err)
			require.NoError(t, f.Close()) // pre-close so the next Close fails
			return f, nil
		}
		t.Setenv(readyFileEnv, path)

		err := signalReady()
		require.ErrorContains(t, err, path)
		require.ErrorContains(t, err, "close")
		require.NoFileExists(t, path, "sentinel must not appear when close fails")

		entries, rerr := os.ReadDir(dir)
		require.NoError(t, rerr)
		require.Empty(t, entries, "leftover temp file must be removed on close failure")
	})
}
