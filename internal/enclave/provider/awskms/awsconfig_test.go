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

package awskms

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/stretchr/testify/require"
)

func TestBuildConfig_HappyPath(t *testing.T) {
	creds := &pb.AwsCredentials{
		AccessKeyId:     "AKIA-test",
		SecretAccessKey: "secret",
		SessionToken:    "session",
		Region:          "us-east-1",
	}
	cfg, err := BuildConfig(creds, "http://127.0.0.1:9000", false)
	require.NoError(t, err)
	require.Equal(t, "us-east-1", cfg.Region)
	// BaseEndpoint stays nil so the SDK keeps the natural KMS endpoint;
	// TLS SNI and SigV4 Host then use kms.<region>.amazonaws.com.
	require.Nil(t, cfg.BaseEndpoint)
	require.NotNil(t, cfg.Credentials)
	require.NotNil(t, cfg.HTTPClient)

	got, err := cfg.Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	require.Equal(t, "AKIA-test", got.AccessKeyID)
	require.Equal(t, "secret", got.SecretAccessKey)
	require.Equal(t, "session", got.SessionToken)
}

func TestBuildConfig_RejectsInvalidCredentialsRegion(t *testing.T) {
	tests := []string{
		"us@east-1",
		"s3",
	}

	for _, region := range tests {
		t.Run(region, func(t *testing.T) {
			creds := &pb.AwsCredentials{
				AccessKeyId:     "AKIA-test",
				SecretAccessKey: "secret",
				SessionToken:    "session",
				Region:          region,
			}

			cfg, err := BuildConfig(creds, "http://127.0.0.1:9000", false)

			require.ErrorIs(t, err, ErrInvalidRegion)
			require.Empty(t, cfg.Region)
		})
	}
}

// TestBuildConfig_Localstack pins the LocalStack base endpoint.
func TestBuildConfig_Localstack(t *testing.T) {
	creds := &pb.AwsCredentials{
		AccessKeyId:     "AKIA-test",
		SecretAccessKey: "secret",
		SessionToken:    "session",
		Region:          "us-east-1",
	}
	cfg, err := BuildConfig(creds, "http://127.0.0.1:9000", true)
	require.NoError(t, err)
	require.NotNil(t, cfg.BaseEndpoint)
	require.Equal(t, "http://127.0.0.1:9000", *cfg.BaseEndpoint)
}

// TestBuildConfig_HTTPClientRedirectsDial pins the DialContext rewrite:
// regardless of the address the SDK passes (kms.<region>.amazonaws.com:443
// in practice), the transport must dial the awsproxy host instead.
func TestAwsproxyHTTPClientWritesRouteBeforePayload(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	wantRoute := byteproxy.AWSRoute{Service: "kms", Region: "us-west-2"}
	client, err := newAwsproxyHTTPClient("http://"+ln.Addr().String(), &wantRoute, "")
	require.NoError(t, err)

	// BuildableClient so the SDK's per-request timeout still attaches; its
	// transport carries the dial redirect.
	transport := client.GetTransport()

	conn, err := transport.DialContext(context.Background(), "tcp", "kms.us-east-1.amazonaws.com:443")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	accepted, err := ln.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = accepted.Close() })
	gotRoute, err := byteproxy.ReadAWSRoute(accepted)
	require.NoError(t, err)
	require.Equal(t, wantRoute, gotRoute)

	payload := []byte("tls-client-hello")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	gotPayload := make([]byte, len(payload))
	_, err = io.ReadFull(accepted, gotPayload)
	require.NoError(t, err)
	require.Equal(t, payload, gotPayload)
}

func TestAwsproxyHTTPClientPropagatesDialFailure(t *testing.T) {
	client, err := newAwsproxyHTTPClient("http://127.0.0.1:0", nil, "")
	require.NoError(t, err)

	conn, err := client.GetTransport().DialContext(
		context.Background(),
		"tcp",
		"kms.us-east-1.amazonaws.com:443",
	)
	require.Error(t, err)
	require.Nil(t, conn)
}

func TestAwsproxyHTTPClientUsesRestrictedRootsForKMS(t *testing.T) {
	const serverName = "kms.us-east-1.amazonaws.com"

	client, err := newAwsproxyHTTPClient("http://127.0.0.1:9000", nil, serverName)
	require.NoError(t, err)

	tlsConfig := client.GetTransport().TLSClientConfig
	require.NotNil(t, tlsConfig)
	require.Equal(t, serverName, tlsConfig.ServerName)
	require.NotNil(t, tlsConfig.RootCAs)
}

func TestAwsproxyHTTPClientRejectsTLSCertificateFromAnotherRoot(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("request reached the server with an unapproved certificate")
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{newForeignKMSTLSCertificate(t)},
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	client, err := newAwsproxyHTTPClient(server.URL, nil, "kms.us-east-1.amazonaws.com")
	require.NoError(t, err)
	client = client.WithTransportOptions(func(transport *http.Transport) {
		transport.Proxy = nil
	})
	request, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://kms.us-east-1.amazonaws.com",
		nil,
	)
	require.NoError(t, err)

	response, err := client.Do(request)
	if response != nil {
		t.Cleanup(func() { _ = response.Body.Close() })
	}
	require.Error(t, err)
	var unknownAuthority x509.UnknownAuthorityError
	require.ErrorAs(t, err, &unknownAuthority)
}

func TestBuildConfig_MalformedEndpoint(t *testing.T) {
	creds := &pb.AwsCredentials{
		AccessKeyId:     "AKIA-test",
		SecretAccessKey: "secret",
		SessionToken:    "session",
		Region:          "us-east-1",
	}
	// no scheme, no host
	cfg, err := BuildConfig(creds, "://bad", false)
	require.Error(t, err)
	require.Empty(t, cfg.Region)
}

// TestBuildConfig_EndpointMissingPort pins the port guard: a host without an
// explicit port would otherwise dial-fail later with an opaque "missing port
// in address", so New must reject it up front.
func TestBuildConfig_EndpointMissingPort(t *testing.T) {
	creds := &pb.AwsCredentials{
		AccessKeyId:     "AKIA-test",
		SecretAccessKey: "secret",
		SessionToken:    "session",
		Region:          "us-east-1",
	}
	cfg, err := BuildConfig(creds, "http://127.0.0.1", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no port")
	require.Empty(t, cfg.Region)
}

func TestBuildConfig_NilCredentials(t *testing.T) {
	cfg, err := BuildConfig(nil, "http://127.0.0.1:9000", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil credentials")
	require.Empty(t, cfg.Region)
}

func TestBuildConfig_EmptyEndpoint(t *testing.T) {
	creds := &pb.AwsCredentials{
		AccessKeyId:     "AKIA-test",
		SecretAccessKey: "secret",
		SessionToken:    "session",
		Region:          "us-east-1",
	}
	cfg, err := BuildConfig(creds, "", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty awsproxy endpoint")
	require.Empty(t, cfg.Region)
}
