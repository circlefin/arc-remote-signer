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

package interceptor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/url"
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/replica"
	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	testSignMethod  = "/arc.signer.v2.SignerService/Sign"
	testReplicaName = "spiffe://circle/validators/validator-01/replicas/a"
)

func TestWithReplicaIdentity_AddsRequestNameToContext(t *testing.T) {
	got, handlerCalled, err := invokeReplicaIdentityInterceptor(
		context.Background(), testSignMethod, false,
		&signerv2.SignRequest{ReplicaName: "validator-01-a"},
	)

	require.NoError(t, err)
	require.True(t, handlerCalled)
	require.Equal(t, "validator-01-a", got.String())
}

func TestWithReplicaIdentity_ContinuesWhenCertificateNameCheckFails(t *testing.T) {
	tests := map[string]context.Context{
		"missing peer":    context.Background(),
		"missing URI SAN": verifiedPeerContext(t, certificateWithURIs(t, 1)),
		"multiple URI SANs": verifiedPeerContext(t, certificateWithURIs(
			t, 1, testReplicaName, "spiffe://circle/validators/validator-01/replicas/b",
		)),
		"different URI SAN": verifiedPeerContext(t, certificateWithURIs(
			t, 1, "spiffe://circle/validators/validator-01/replicas/b",
		)),
	}

	for name, ctx := range tests {
		t.Run(name, func(t *testing.T) {
			got, handlerCalled, err := invokeReplicaIdentityInterceptor(
				ctx, testSignMethod, true,
				&signerv2.SignRequest{ReplicaName: testReplicaName},
			)

			require.NoError(t, err)
			require.True(t, handlerCalled)
			require.Equal(t, testReplicaName, got.String())
		})
	}
}

func TestCertificateNameStatus(t *testing.T) {
	tests := map[string]struct {
		ctx  context.Context
		want certificateNameStatus
	}{
		"matching URI SAN": {
			ctx:  verifiedPeerContext(t, certificateWithURIs(t, 1, testReplicaName)),
			want: certificateNameMatch,
		},
		"rotated certificate": {
			ctx:  verifiedPeerContext(t, certificateWithURIs(t, 2, testReplicaName)),
			want: certificateNameMatch,
		},
		"missing peer": {ctx: context.Background(), want: certificateNameMissing},
		"non-TLS peer": {
			ctx:  peer.NewContext(context.Background(), &peer.Peer{}),
			want: certificateNameMissing,
		},
		"unverified certificate": {
			ctx: peer.NewContext(context.Background(), &peer.Peer{
				AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{certificateWithURIs(t, 1, testReplicaName)},
				}},
			}),
			want: certificateNameMissing,
		},
		"missing URI SAN": {
			ctx:  verifiedPeerContext(t, certificateWithURIs(t, 1)),
			want: certificateNameMissing,
		},
		"relative URI SAN": {
			ctx: verifiedPeerContext(t, &x509.Certificate{
				SerialNumber: big.NewInt(1),
				URIs:         []*url.URL{{Path: "/validators/validator-01/replicas/a"}},
			}),
			want: certificateNameMissing,
		},
		"multiple URI SANs": {
			ctx: verifiedPeerContext(t, certificateWithURIs(
				t, 1, testReplicaName, "spiffe://circle/validators/validator-01/replicas/b",
			)),
			want: certificateNameAmbiguous,
		},
		"different URI SAN": {
			ctx: verifiedPeerContext(t, certificateWithURIs(
				t, 1, "spiffe://circle/validators/validator-01/replicas/b",
			)),
			want: certificateNameMismatch,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tt.want, certificateNameStatusFromPeer(tt.ctx, testReplicaName))
		})
	}
}

func TestWithReplicaIdentity_RejectsInvalidRequestName(t *testing.T) {
	_, handlerCalled, err := invokeReplicaIdentityInterceptor(
		context.Background(), testSignMethod, false,
		&signerv2.SignRequest{ReplicaName: "validator 01"},
	)

	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(t, "invalid replica name", status.Convert(err).Message())
	require.False(t, handlerCalled)
}

func TestWithReplicaIdentity_BypassesOtherMethods(t *testing.T) {
	got, handlerCalled, err := invokeReplicaIdentityInterceptor(
		context.Background(), "/arc.signer.v2.SignerService/PublicKey", true, nil,
	)

	require.NoError(t, err)
	require.True(t, handlerCalled)
	require.Empty(t, got)
}

func invokeReplicaIdentityInterceptor(
	ctx context.Context,
	method string,
	checkCertificate bool,
	req interface{},
) (replica.ID, bool, error) {
	var got replica.ID
	handlerCalled := false
	interceptor := WithReplicaIdentity(testSignMethod, checkCertificate)
	_, err := interceptor(
		ctx, req, &grpc.UnaryServerInfo{FullMethod: method},
		func(ctx context.Context, _ interface{}) (interface{}, error) {
			handlerCalled = true
			got, _ = replica.FromContext(ctx)
			return nil, nil
		},
	)
	return got, handlerCalled, err
}

func verifiedPeerContext(t *testing.T, certificate *x509.Certificate) context.Context {
	t.Helper()
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{certificate}},
		}},
	})
}

func certificateWithURIs(t *testing.T, serial int64, rawURIs ...string) *x509.Certificate {
	t.Helper()

	certificate := &x509.Certificate{SerialNumber: big.NewInt(serial)}
	for _, rawURI := range rawURIs {
		uri, err := url.Parse(rawURI)
		require.NoError(t, err)
		certificate.URIs = append(certificate.URIs, uri)
	}
	return certificate
}
