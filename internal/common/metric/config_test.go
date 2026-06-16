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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewConfig_DefaultValues(t *testing.T) {
	t.Setenv("DD_SERVICE", "svc")
	t.Setenv("DD_ENV", "dev")
	t.Setenv("DD_VERSION", "1.2.3")

	cfg := NewConfig()
	require.Equal(t, "circle.platform_common_go", cfg.Statsd.Namespace)
	require.Equal(t, "127.0.0.1:8125", cfg.Statsd.GetAddr())
	require.Len(t, cfg.Statsd.GlobalTags, 3)
	require.ElementsMatch(t, []string{"service:svc", "env:dev", "version:1.2.3"}, cfg.Statsd.GlobalTags)
}

func TestNewConfig_SkipsEmptyGlobalTags(t *testing.T) {
	t.Setenv("DD_SERVICE", "")
	t.Setenv("DD_ENV", "")
	t.Setenv("DD_VERSION", "")

	cfg := NewConfig()
	require.Empty(t, cfg.Statsd.GlobalTags)
}

func TestNewConfig_SkipsWhitespaceGlobalTags(t *testing.T) {
	t.Setenv("DD_SERVICE", "  ")
	t.Setenv("DD_ENV", " \t ")
	t.Setenv("DD_VERSION", "\n")

	cfg := NewConfig()
	require.Empty(t, cfg.Statsd.GlobalTags)
}

func TestStatsdConfig_UnixAddrHost(t *testing.T) {
	cfg := NewConfig()
	cfg.Statsd.Host = "unix://foo"
	require.Equal(t, "unix://foo", cfg.Statsd.GetAddr())
}

func TestNewConfig_PrometheusDefaults(t *testing.T) {
	cfg := NewConfig()
	require.NotNil(t, cfg.Prometheus)
	require.False(t, cfg.Prometheus.Enabled)
	require.Equal(t, "0.0.0.0", cfg.Prometheus.Host)
	require.Equal(t, 9090, cfg.Prometheus.Port)
	require.Equal(t, "/metrics", cfg.Prometheus.Path)
}

func TestConfig_IsPrometheusEnabled(t *testing.T) {
	tests := map[string]struct {
		prometheus *PrometheusConfig
		want       bool
	}{
		"nil config": {prometheus: nil, want: false},
		"disabled":   {prometheus: &PrometheusConfig{Enabled: false}, want: false},
		"enabled":    {prometheus: &PrometheusConfig{Enabled: true}, want: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := &Config{Prometheus: tt.prometheus}
			require.Equal(t, tt.want, cfg.IsPrometheusEnabled())
		})
	}
}

func TestPrometheusConfig_GetAddr(t *testing.T) {
	cfg := &PrometheusConfig{Host: "0.0.0.0", Port: 9090}
	require.Equal(t, "0.0.0.0:9090", cfg.GetAddr())
}

func TestPrometheusConfig_GetPath(t *testing.T) {
	t.Run("returns configured path", func(t *testing.T) {
		cfg := &PrometheusConfig{Path: "/custom"}
		require.Equal(t, "/custom", cfg.GetPath())
	})

	t.Run("defaults when empty", func(t *testing.T) {
		cfg := &PrometheusConfig{Path: ""}
		require.Equal(t, "/metrics", cfg.GetPath())
	})
}
