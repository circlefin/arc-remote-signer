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

package metric

import (
	"context"
	"sync"
	"time"

	ddstatsd "github.com/DataDog/datadog-go/v5/statsd"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
)

var (
	statsMu     sync.Mutex
	statsGlobal StatsService
)

// GetStatsService returns the global StatsService singleton, initializing a default
// Datadog client on first access.
func GetStatsService() StatsService {
	statsMu.Lock()
	defer statsMu.Unlock()

	if statsGlobal == nil {
		cfg := NewConfig()
		statsService, err := NewDatadogStatsD(cfg.Statsd)
		if err != nil {
			logging.Get("common.metric").Error(context.Background(), "failed to initialize default StatsService", logging.Entries{})
			panic(err)
		}
		statsGlobal = statsService
	}

	return statsGlobal
}

// SetStatsService overrides the global StatsService, typically for tests.
func SetStatsService(stats StatsService) {
	statsMu.Lock()
	defer statsMu.Unlock()
	statsGlobal = stats
}

// NewDatadogStatsD builds a StatsService backed by Datadog statsd.
func NewDatadogStatsD(cfg *DatadogStatsdConfig) (StatsService, error) {
	options := []ddstatsd.Option{ddstatsd.WithNamespace(cfg.Namespace)}
	if cfg.TelemetryDisabled {
		options = append(options, ddstatsd.WithoutTelemetry())
	}
	if len(cfg.GlobalTags) != 0 {
		options = append(options, ddstatsd.WithTags(cfg.GlobalTags))
	}

	client, err := ddstatsd.New(cfg.GetAddr(), options...)
	if err != nil {
		return nil, err
	}

	return &DatadogStatsD{client: client}, nil
}

// DatadogStatsD is a StatsService implementation backed by Datadog statsd.
type DatadogStatsD struct {
	client ddstatsd.ClientInterface
}

// Timing submits a timing metric with the provided name and tags.
func (d *DatadogStatsD) Timing(name string, value time.Duration, tags []string) {
	if err := d.client.Timing(name, value, tags, 1); err != nil {
		// statsd is best-effort; log at debug to avoid noise
		_ = err // intentionally ignored: statsd is fire-and-forget over UDP
	}
}

// Distribution submits a distribution metric with the provided name and tags.
func (d *DatadogStatsD) Distribution(name string, value int64, tags []string) {
	if err := d.client.Distribution(name, float64(value), tags, 1); err != nil {
		// statsd is best-effort; log at debug to avoid noise
		_ = err // intentionally ignored: statsd is fire-and-forget over UDP
	}
}
