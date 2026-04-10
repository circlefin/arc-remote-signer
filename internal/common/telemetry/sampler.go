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

	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type customSampler struct {
	defaultSampler          sdktrace.Sampler
	convertDropToRecordOnly bool
}

func (customSampler) Description() string {
	return "CustomSampler"
}

func initCustomSampler(config Config) sdktrace.Sampler {
	logger := logging.Get("tracer")
	var defaultSampler sdktrace.Sampler
	if config.GoAutoInstrumentation {
		ratio := config.TracerSamplerRatio
		ratioSampler := sdktrace.TraceIDRatioBased(ratio)
		defaultSampler = sdktrace.ParentBased(
			ratioSampler,
			sdktrace.WithRemoteParentNotSampled(ratioSampler),
			sdktrace.WithLocalParentNotSampled(ratioSampler),
		)
		logger.Info(context.Background(), "Initialized parent based tracer default sampler with trace ID ratio (resample when parent not sampled).",
			logging.Entries{"ratio": ratio})
	} else {
		defaultSampler = sdktrace.NeverSample()
		logger.Info(context.Background(), "Initialized no-ops tracer default sampler.", nil)
	}
	return &customSampler{
		defaultSampler:          defaultSampler,
		convertDropToRecordOnly: config.ConvertDropToRecordOnly,
	}
}

func (cs customSampler) ShouldSample(p sdktrace.SamplingParameters) sdktrace.SamplingResult {
	sr := cs.defaultSampler.ShouldSample(p)
	if cs.convertDropToRecordOnly && sr.Decision == sdktrace.Drop {
		sr.Decision = sdktrace.RecordOnly
	}
	return sr
}
