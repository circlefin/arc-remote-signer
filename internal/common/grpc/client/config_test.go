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

package client

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestNewClientConfigDefaults(t *testing.T) {
	cfg := NewClientConfig("enclave", "http://localhost:10350")

	require.NotNil(t, cfg)
	require.Equal(t, "enclave", cfg.Name)
	require.Equal(t, "http://localhost:10350", cfg.BaseURL)
	require.Equal(t, 5000, cfg.RequestTimeoutMS)
	require.NotNil(t, cfg.Retry)
	require.Equal(t, uint(1), cfg.Retry.MaxAttempts)
	require.Equal(t, []codes.Code{
		codes.Unavailable,
		codes.DeadlineExceeded,
		codes.Internal,
	}, cfg.Retry.RetryCodes)
}

func TestNewClientConfigReturnsIndependentRetrySlices(t *testing.T) {
	first := NewClientConfig("a", "http://a")
	second := NewClientConfig("b", "http://b")

	first.Retry.RetryCodes[0] = codes.Aborted
	require.Equal(t, codes.Unavailable, second.Retry.RetryCodes[0])
}

func TestConfig_MethodsConfiguration(t *testing.T) {
	cfg := &Config{
		RequestTimeoutMS: 500,
		Methods: map[string]MethodConfig{
			"Initialize":   {TimeoutMS: 30000},
			"GenerateKey":  {TimeoutMS: 30000, MaxAttempts: 1},
			"GetPublicKey": {TimeoutMS: 30000},
			"SignMessage":  {TimeoutMS: 500, MaxAttempts: 1},
		},
	}

	require.Equal(t, 500, cfg.RequestTimeoutMS)
	require.Equal(t, 30000, cfg.Methods["Initialize"].TimeoutMS)
	require.Equal(t, 30000, cfg.Methods["GenerateKey"].TimeoutMS)
	require.Equal(t, uint(1), cfg.Methods["GenerateKey"].MaxAttempts)
	require.Equal(t, 30000, cfg.Methods["GetPublicKey"].TimeoutMS)
	require.Equal(t, 500, cfg.Methods["SignMessage"].TimeoutMS)
	require.Equal(t, uint(1), cfg.Methods["SignMessage"].MaxAttempts)
}
