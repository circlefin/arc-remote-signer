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
	"strings"

	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"go.opentelemetry.io/otel/propagation"
)

// GetPropagator returns tracing propagator.
func GetPropagator(propagatorsStr string) propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(getPropagatorsFromString(propagatorsStr)...)
}

func getPropagatorsFromString(propagators string) []propagation.TextMapPropagator {
	var res []propagation.TextMapPropagator
	logger := logging.Get("tracer")
	for _, s := range strings.Split(propagators, ",") {
		if s == "" {
			continue
		}
		var propagator propagation.TextMapPropagator
		switch s {
		case "tracecontext":
			propagator = propagation.TraceContext{}
		case "baggage":
			propagator = propagation.Baggage{}
		default:
			logger.Warn(context.Background(), "Cannot recognize propagator, skipping.", logging.Entries{"propagator": s})
			continue
		}
		res = append(res, propagator)
	}
	if res == nil {
		res = []propagation.TextMapPropagator{propagation.TraceContext{}, propagation.Baggage{}}
	}
	return res
}
