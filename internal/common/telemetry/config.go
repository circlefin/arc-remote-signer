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
	"os"
	"strings"
)

const defaultPropagators = "tracecontext,baggage"

// Config provides telemetry configuration.
type Config struct {
	GoAutoInstrumentation   bool    `mapstructure:"goAutoInstrumentation"`
	TracerSamplerRatio      float64 `mapstructure:"tracerSamplerRatio"`
	Propagators             string  `mapstructure:"propagators"`
	Disabled                bool    `mapstructure:"disabled"`
	ConvertDropToRecordOnly bool    `mapstructure:"convertDropToRecordOnly"`
}

// NewConfig returns telemetry defaults compatible with platform-common.
func NewConfig() *Config {
	return &Config{
		GoAutoInstrumentation:   true,
		TracerSamplerRatio:      0.5,
		Propagators:             defaultPropagators,
		ConvertDropToRecordOnly: false,
		Disabled:                strings.EqualFold(os.Getenv("CI"), "true"),
	}
}
