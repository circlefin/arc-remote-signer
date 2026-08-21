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

package vsockproxy

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRun_ReadinessSignalFailureAborts verifies that Run returns an error
// when it cannot write the readiness file.
func TestRun_ReadinessSignalFailureAborts(t *testing.T) {
	// Parent directory does not exist, so os.Create fails and signalReady
	// returns an error carrying the path.
	path := filepath.Join(t.TempDir(), "no-such-dir", "vsockproxy.ready")
	t.Setenv(readyFileEnv, path)

	cfg := &Config{
		Vsockproxy: Vsockproxy{BasePort: 0, MaxConns: 1},
		Provider: ProviderConfig{AWSKMS: ProviderAWSKMSConfig{
			Arns: []string{"arn:aws:kms:us-east-1:000000000000:key/test"},
		}},
	}

	err := Run(cfg)
	require.ErrorContains(t, err, path)
}
