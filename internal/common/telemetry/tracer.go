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

// Package telemetry provides OpenTelemetry tracer initialization and helpers.
package telemetry

import (
	"context"

	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

// InitTracer initializes OpenTelemetry tracer provider and propagators.
func InitTracer(serviceName string, config Config) (func(), error) {
	logger := logging.Get("tracer")
	ctx := context.Background()

	if config.Disabled {
		logger.Info(ctx, "tracer initialization skipped", nil)
		return func() {
			// no-op: telemetry is disabled, so no tracer provider was initialized.
		}, nil
	}

	traceExporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		logger.ErrorErr(ctx, "Failed to initialize trace exporter.", err, nil)
		return nil, err
	}

	resources, err := resource.New(
		ctx,
		resource.WithOS(),
		resource.WithHost(),
		resource.WithProcess(),
		resource.WithSchemaURL(semconv.SchemaURL),
		resource.WithAttributes(semconv.ServiceNameKey.String(serviceName)),
	)
	if err != nil {
		logger.ErrorErr(ctx, "Failed to initialize tracer resources.", err, nil)
		return nil, err
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithSampler(initCustomSampler(config)),
		sdktrace.WithResource(resources),
	)

	otel.SetTracerProvider(tracerProvider)
	otel.SetTextMapPropagator(GetPropagator(config.Propagators))

	return func() {
		if err := tracerProvider.Shutdown(ctx); err != nil {
			logger.ErrorErr(ctx, "Failed to shutdown tracer provider", err, nil)
		}
	}, nil
}
