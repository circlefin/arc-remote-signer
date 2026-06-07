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
	"fmt"
	"os"
	"strings"

	ddstatsd "github.com/DataDog/datadog-go/v5/statsd"
)

// DatadogStatsdConfig defines connection and tagging options for the Datadog
// statsd client.
type DatadogStatsdConfig struct {
	Enabled           bool     `mapstructure:"enabled"`
	Host              string   `mapstructure:"host"`
	Port              string   `mapstructure:"port"`
	Namespace         string   `mapstructure:"namespace"`
	TelemetryDisabled bool     `mapstructure:"telemetryDisabled"`
	GlobalTags        []string `mapstructure:"globalTags"`
}

// PrometheusConfig defines the configuration for exposing metrics with Prometheus.
type PrometheusConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Host    string `mapstructure:"host"`
	Port    uint32 `mapstructure:"port"`
	Path    string `mapstructure:"path"`
}

// Config is the root metric configuration consumed by application bootstrap.
type Config struct {
	Statsd     *DatadogStatsdConfig `mapstructure:"statsd"`
	Prometheus *PrometheusConfig    `mapstructure:"prometheus"`
}

// NewConfig returns the default metric configuration used by this service.
func NewConfig() *Config {
	globalTags := make([]string, 0, 3)
	for _, tag := range []struct {
		key string
		env string
	}{
		{key: "service", env: "DD_SERVICE"},
		{key: "env", env: "DD_ENV"},
		{key: "version", env: "DD_VERSION"},
	} {
		if value := strings.TrimSpace(os.Getenv(tag.env)); value != "" {
			globalTags = append(globalTags, tag.key+":"+value)
		}
	}

	return &Config{
		Statsd: &DatadogStatsdConfig{
			Enabled:           true,
			Host:              "127.0.0.1",
			Port:              "8125",
			Namespace:         "circle.platform_common_go",
			TelemetryDisabled: false,
			GlobalTags:        globalTags,
		},
		Prometheus: &PrometheusConfig{
			Enabled: false,
			Host:    "127.0.0.1",
			Port:    9090,
			Path:    "/metrics",
		},
	}
}

// IsStatsdEnabled returns true if statsd is enabled.
func (cfg *Config) IsStatsdEnabled() bool {
	return cfg.Statsd != nil && cfg.Statsd.Enabled
}

// IsPrometheusEnabled returns true if prometheus is enabled.
func (cfg *Config) IsPrometheusEnabled() bool {
	return cfg.Prometheus != nil && cfg.Prometheus.Enabled
}

// GetAddr returns the statsd destination in host:port or unix socket format.
func (cfg *DatadogStatsdConfig) GetAddr() string {
	if strings.HasPrefix(cfg.Host, ddstatsd.UnixAddressPrefix) {
		return cfg.Host
	}
	return fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
}

// GetAddr returns the prometheus destination in host:port format.
func (cfg *PrometheusConfig) GetAddr() string {
	return fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
}

// GetPath returns the prometheus path.
func (cfg *PrometheusConfig) GetPath() string {
	if cfg.Path == "" {
		return "/metrics"
	}
	return cfg.Path
}
