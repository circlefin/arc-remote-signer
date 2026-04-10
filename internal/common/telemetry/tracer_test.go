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
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

func TestGetInstrumentedTransport_NotNil(t *testing.T) {
	rt := GetInstrumentedTransport(http.DefaultTransport)
	require.NotNil(t, rt)
}

func TestInitTracer_DisabledIsNoop(t *testing.T) {
	cleanup, err := InitTracer("test-service", Config{Disabled: true})
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	require.NotPanics(t, func() { cleanup() })
}

func TestInitTracer_EnabledSetsPropagator(t *testing.T) {
	originalProvider := otel.GetTracerProvider()
	originalPropagator := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(originalProvider)
		otel.SetTextMapPropagator(originalPropagator)
	})

	cfg := Config{
		GoAutoInstrumentation: false,
		Propagators:           "tracecontext,baggage",
	}

	cleanup, err := InitTracer("test-service", cfg)
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	require.NotPanics(t, func() { cleanup() })

	fields := otel.GetTextMapPropagator().Fields()
	require.Contains(t, fields, "traceparent")
	require.Contains(t, fields, "baggage")
}
