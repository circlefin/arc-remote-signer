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

package metrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/circlefin/arc-remote-signer/internal/common/metric"
	"github.com/stretchr/testify/require"
)

func enabledConfig(path string) *metric.Config {
	return &metric.Config{
		Prometheus: &metric.PrometheusConfig{
			Enabled: true,
			Host:    "127.0.0.1",
			// Port 0 lets the OS choose a free port for the test listener.
			Port: 0,
			Path: path,
		},
	}
}

func TestNew_DisabledReturnsNilRunnable(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		runnable, err := New(nil, metric.NewPrometheus())
		require.NoError(t, err)
		require.Nil(t, runnable)
	})

	t.Run("prometheus disabled", func(t *testing.T) {
		cfg := &metric.Config{Prometheus: &metric.PrometheusConfig{Enabled: false}}
		runnable, err := New(cfg, metric.NewPrometheus())
		require.NoError(t, err)
		require.Nil(t, runnable)
	})
}

func TestNew_ErrorsWhenProviderMissing(t *testing.T) {
	runnable, err := New(enabledConfig("/metrics"), nil)
	require.Error(t, err)
	require.Nil(t, runnable)
}

func TestNew_ErrorsWhenPathInvalid(t *testing.T) {
	runnable, err := New(enabledConfig("metrics"), metric.NewPrometheus())
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid metrics configuration")
	require.Nil(t, runnable)
}

func TestServer_Lifecycle(t *testing.T) {
	srv, err := New(enabledConfig("/metrics"), metric.NewPrometheus())
	require.NoError(t, err)
	require.NotNil(t, srv)
	require.Equal(t, "metrics", srv.Name())

	server, ok := srv.(*Server)
	require.True(t, ok)

	require.NoError(t, srv.Run())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("shutdown returned error: %v", err)
		}
	})

	url := fmt.Sprintf("http://%s/metrics", server.listener.Addr().String())
	body := getWithRetry(t, url)
	require.Contains(t, body, "go_goroutines")
}

// getWithRetry polls the endpoint until it serves a response, tolerating the
// brief window before the goroutine-started listener is ready.
func getWithRetry(t *testing.T, url string) string {
	t.Helper()

	var lastErr error
	for range 20 {
		resp, err := http.Get(url) //nolint:noctx // short-lived test request
		if err != nil {
			lastErr = err
			time.Sleep(10 * time.Millisecond)
			continue
		}
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return string(data)
	}
	require.FailNow(t, "metrics endpoint never became ready", lastErr)
	return ""
}
