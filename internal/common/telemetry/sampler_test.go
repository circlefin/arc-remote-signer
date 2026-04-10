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
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func TestCustomSampler_ConvertDropToRecordOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                    string
		convertDropToRecordOnly bool
		wantDecision            sdktrace.SamplingDecision
	}{
		{
			name:                    "convert drop to record only",
			convertDropToRecordOnly: true,
			wantDecision:            sdktrace.RecordOnly,
		},
		{
			name:                    "keep drop when convert disabled",
			convertDropToRecordOnly: false,
			wantDecision:            sdktrace.Drop,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			sampler := initCustomSampler(Config{
				GoAutoInstrumentation:   false,
				ConvertDropToRecordOnly: tt.convertDropToRecordOnly,
			})

			result := sampler.ShouldSample(sdktrace.SamplingParameters{
				ParentContext: context.Background(),
				TraceID:       oteltrace.TraceID{1},
				Name:          "test",
			})
			require.Equal(t, tt.wantDecision, result.Decision)
		})
	}
}

func TestCustomSampler_Description(t *testing.T) {
	sampler := initCustomSampler(Config{GoAutoInstrumentation: false})
	require.Equal(t, "CustomSampler", sampler.Description())
}

func TestInitCustomSampler_GoAutoInstrumentation(t *testing.T) {
	tests := []struct {
		name         string
		ratio        float64
		wantDecision sdktrace.SamplingDecision
	}{
		{
			name:         "ratio 1 always samples",
			ratio:        1.0,
			wantDecision: sdktrace.RecordAndSample,
		},
		{
			name:         "ratio 0 drops",
			ratio:        0.0,
			wantDecision: sdktrace.Drop,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			sampler := initCustomSampler(Config{
				GoAutoInstrumentation:   true,
				TracerSamplerRatio:      tt.ratio,
				ConvertDropToRecordOnly: false,
			})

			result := sampler.ShouldSample(sdktrace.SamplingParameters{
				ParentContext: context.Background(),
				TraceID:       oteltrace.TraceID{1},
				Name:          "test",
			})
			require.Equal(t, tt.wantDecision, result.Decision)
		})
	}
}

func TestInitCustomSampler_ResamplesWhenParentNotSampled(t *testing.T) {
	tid := oteltrace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	sid := oteltrace.SpanID{1, 2, 3, 4, 5, 6, 7, 8}

	tests := []struct {
		name          string
		parentContext context.Context
	}{
		{
			name: "remote parent not sampled still honors ratio",
			parentContext: oteltrace.ContextWithSpanContext(context.Background(),
				oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
					TraceID:    tid,
					SpanID:     sid,
					TraceFlags: 0,
					Remote:     true,
				})),
		},
		{
			name: "local parent not sampled still honors ratio",
			parentContext: oteltrace.ContextWithSpanContext(context.Background(),
				oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
					TraceID:    tid,
					SpanID:     sid,
					TraceFlags: 0,
					Remote:     false,
				})),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			sampler := initCustomSampler(Config{
				GoAutoInstrumentation:   true,
				TracerSamplerRatio:      1.0,
				ConvertDropToRecordOnly: false,
			})

			got := sampler.ShouldSample(sdktrace.SamplingParameters{
				ParentContext: tt.parentContext,
				TraceID:       tid,
				Name:          "test",
			}).Decision
			require.Equal(t, sdktrace.RecordAndSample, got)
		})
	}
}
