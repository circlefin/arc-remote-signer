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

package enclave

import (
	"testing"

	grpcClient "github.com/circlefin/arc-remote-signer/internal/common/grpc/client"
	"github.com/stretchr/testify/require"
)

func TestNew_Success(t *testing.T) {
	cfg := NewProviderConfig()
	cfg.Client.BaseURL = ":10350"

	client, conn, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
	require.NotNil(t, conn)
	require.NoError(t, conn.Close())
}

func TestNew_NilProviderConfig(t *testing.T) {
	client, conn, err := New(nil)

	require.Nil(t, client)
	require.Nil(t, conn)
	require.Error(t, err)
	require.EqualError(t, err, "provider config is nil")
}

func TestNew_NilClientConfig(t *testing.T) {
	client, conn, err := New(&ProviderConfig{})

	require.Nil(t, client)
	require.Nil(t, conn)
	require.Error(t, err)
	require.EqualError(t, err, "provider client config is nil")
}

func TestNew_NitroEnabledWithInvalidCID(t *testing.T) {
	cfg := NewProviderConfig()
	cfg.NitroEnclave.Enabled = true
	cfg.NitroEnclave.CID = 0

	client, conn, err := New(cfg)

	require.Nil(t, client)
	require.Nil(t, conn)
	require.Error(t, err)
	require.EqualError(t, err, "nitro enclave is enabled but cid or port is invalid")
}

func TestNew_NitroEnabledWithInvalidPort(t *testing.T) {
	cfg := NewProviderConfig()
	cfg.NitroEnclave.Enabled = true
	cfg.NitroEnclave.CID = 16
	cfg.NitroEnclave.Port = 0

	client, conn, err := New(cfg)

	require.Nil(t, client)
	require.Nil(t, conn)
	require.Error(t, err)
	require.EqualError(t, err, "nitro enclave is enabled but cid or port is invalid")
}

func TestNew_InvalidTarget(t *testing.T) {
	cfg := &ProviderConfig{
		NitroEnclave: &NitroEnclave{},
		Client: &grpcClient.Config{
			BaseURL: "http://localhost:10350",
		},
	}

	client, conn, err := New(cfg)
	require.Nil(t, client)
	require.Nil(t, conn)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to create enclave client connection")
}
