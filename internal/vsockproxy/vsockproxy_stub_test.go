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

//go:build !linux

package vsockproxy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// stubCfg returns a valid config for the TCP stub.
func stubCfg() *Config {
	return &Config{
		Vsockproxy: Vsockproxy{BasePort: 0, MaxConns: 1},
		Provider: ProviderConfig{AWSKMS: ProviderAWSKMSConfig{
			Arns: []string{"arn:aws:kms:us-east-1:000000000000:key/test"},
		}},
	}
}

func TestNew_NilConfigErrors(t *testing.T) {
	_, err := New(nil, WithTCPTransport())
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil config")
}

func TestNew_NoTransportOptionErrors(t *testing.T) {
	_, err := New(stubCfg())
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-Linux requires WithTCPTransport")
}

func TestNew_TCPTransportSucceeds(t *testing.T) {
	p, err := New(stubCfg(), WithTCPTransport())
	require.NoError(t, err)
	require.NotNil(t, p)
}
