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
	"net"
	"os"
	"strconv"
	"strings"

	ddstatsd "github.com/DataDog/datadog-go/v5/statsd"
)

// defaultPrometheusPath is the HTTP path served when none is configured.
const defaultPrometheusPath = "/metrics"

// DatadogStatsdConfig defines connection and tagging options for the Datadog
// statsd client.
type DatadogStatsdConfig struct {
	Host              string   `mapstructure:"host"`
	Port              string   `mapstructure:"port"`
	Namespace         string   `mapstructure:"namespace"`
	TelemetryDisabled bool     `mapstructure:"telemetryDisabled"`
	GlobalTags        []string `mapstructure:"globalTags"`
}

// PrometheusConfig defines the Prometheus metrics HTTP endpoint configuration.
type PrometheusConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Host    string `mapstructure:"host"`
	Port    int    `mapstructure:"port"`
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
			Host:              "127.0.0.1",
			Port:              "8125",
			Namespace:         "circle.platform_common_go",
			TelemetryDisabled: false,
			GlobalTags:        globalTags,
		},
		// Initialized so APP_METRICS_PROMETHEUS_* env overrides bind even when the
		// config file omits the prometheus block. Disabled by default.
		Prometheus: &PrometheusConfig{
			Enabled: false,
			Host:    "0.0.0.0",
			Port:    9090,
			Path:    defaultPrometheusPath,
		},
	}
}

// IsPrometheusEnabled reports whether the Prometheus metrics endpoint is enabled.
func (cfg *Config) IsPrometheusEnabled() bool {
	return cfg.Prometheus != nil && cfg.Prometheus.Enabled
}

// GetAddr returns the host:port the Prometheus metrics server listens on.
func (cfg *PrometheusConfig) GetAddr() string {
	return net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
}

// GetPath returns the configured metrics HTTP path, defaulting to /metrics.
func (cfg *PrometheusConfig) GetPath() string {
	if cfg.Path == "" {
		return defaultPrometheusPath
	}
	return cfg.Path
}

// GetAddr returns the statsd destination in host:port or unix socket format.
func (cfg *DatadogStatsdConfig) GetAddr() string {
	if strings.HasPrefix(cfg.Host, ddstatsd.UnixAddressPrefix) {
		return cfg.Host
	}
	return fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
}
