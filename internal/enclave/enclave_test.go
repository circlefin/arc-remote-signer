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

//go:build !prod

package enclave

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awsproxy"
	"github.com/stretchr/testify/require"
)

func shutdownAWSProxyOnCleanup(t *testing.T, pvd awsproxy.Provider) {
	t.Helper()
	t.Cleanup(func() {
		if err := pvd.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown AWS proxy: %v", err)
		}
	})
}

// TestSelectTransport checks development transport selection.
// Nitro configuration uses VSOCK. Other configuration uses TCP.
func TestSelectTransport(t *testing.T) {
	tests := map[string]struct {
		enabled bool
		want    transportKind
	}{
		"nitro enabled selects vsock": {enabled: true, want: transportVsock},
		"nitro disabled selects tcp":  {enabled: false, want: transportTCP},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.NitroEnclave.Enabled = tt.enabled
			require.Equal(t, tt.want, selectTransport(cfg))
		})
	}
}

func TestBuildAWSProxy_SelectsTCP(t *testing.T) {
	cfg := NewConfig()
	cfg.NitroEnclave.Enabled = false

	pvd, err := buildAWSProxy(cfg)

	require.NoError(t, err)
	require.NotNil(t, pvd)
	shutdownAWSProxyOnCleanup(t, pvd)
}

func TestNewAWSKMSFactory_RequestsFreshRecipientAttestation(t *testing.T) {
	cfg := NewConfig()
	enclavePvd := &recipientAttestationProvider{
		documents: [][]byte{
			[]byte("attestation-document-1"),
			[]byte("attestation-document-2"),
		},
	}
	factory := newAWSKMSFactory(cfg, true, enclavePvd)
	awsCfg := aws.Config{Region: "us-east-1"}
	arns := []string{"arn:aws:kms:us-east-1:123456789012:key/test"}

	first, err := factory(context.Background(), awsCfg, arns)
	require.NoError(t, err)
	second, err := factory(context.Background(), awsCfg, arns)

	require.NoError(t, err)
	require.NotNil(t, first)
	require.NotNil(t, second)
	require.Equal(t, 2, enclavePvd.attestationCalls)
}

type recipientAttestationProvider struct {
	documents        [][]byte
	attestationCalls int
}

func (*recipientAttestationProvider) DecryptKMSEnvelopedKey([]byte) ([]byte, error) {
	return nil, nil
}

func (p *recipientAttestationProvider) AttestKMSRecipient() ([]byte, error) {
	document := p.documents[p.attestationCalls]
	p.attestationCalls++
	return document, nil
}

func (*recipientAttestationProvider) Attest([]byte) ([]byte, error) {
	return nil, nil
}
