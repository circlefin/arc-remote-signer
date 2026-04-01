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

package telemetry

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewConfig_DefaultValues(t *testing.T) {
	t.Parallel()

	cfg := NewConfig()
	require.True(t, cfg.GoAutoInstrumentation)
	require.Equal(t, 0.5, cfg.TracerSamplerRatio)
	require.NotEmpty(t, cfg.Propagators)
	require.Equal(t, defaultPropagators, cfg.Propagators)
	require.False(t, cfg.ConvertDropToRecordOnly)
}

func TestNewConfig_DisabledInCI(t *testing.T) {
	t.Setenv("CI", "true")

	cfg := NewConfig()
	require.True(t, cfg.Disabled)
}
