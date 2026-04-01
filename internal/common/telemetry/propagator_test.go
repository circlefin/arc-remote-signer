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
	"go.opentelemetry.io/otel/propagation"
)

func TestGetPropagatorsFromString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		propagators     string
		wantPropagators []propagation.TextMapPropagator
	}{
		{
			name:            "known propagators",
			propagators:     "tracecontext,baggage",
			wantPropagators: []propagation.TextMapPropagator{propagation.TraceContext{}, propagation.Baggage{}},
		},
		{
			name:            "unknown propagator ignored",
			propagators:     "tracecontext,unknown,baggage",
			wantPropagators: []propagation.TextMapPropagator{propagation.TraceContext{}, propagation.Baggage{}},
		},
		{
			name:            "empty defaults to tracecontext and baggage",
			propagators:     "",
			wantPropagators: []propagation.TextMapPropagator{propagation.TraceContext{}, propagation.Baggage{}},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.wantPropagators, getPropagatorsFromString(tt.propagators))
		})
	}
}
