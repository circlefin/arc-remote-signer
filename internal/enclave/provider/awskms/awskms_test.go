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
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, arn string) *client {
	t.Helper()
	return &client{arn: arn}
}

func newConstructorTestConfig() *Config {
	return &Config{
		Arns: []string{"arn:aws:kms:us-east-1:123456789012:key/test"},
	}
}

func TestNewWithAttestation_RequiresAttestationDocument(t *testing.T) {
	tests := []struct {
		name                string
		attestationDocument []byte
	}{
		{
			name:                "nil document",
			attestationDocument: nil,
		},
		{
			name:                "empty document",
			attestationDocument: []byte{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			gotProvider, err := NewWithAttestation(
				context.Background(),
				newConstructorTestConfig(),
				aws.Config{},
				tt.attestationDocument,
			)

			require.ErrorIs(t, err, ErrAttestationDocumentRequired)
			require.Nil(t, gotProvider)
		})
	}
}

func TestNewWithAttestation_AttachesRecipientInfo(t *testing.T) {
	wantDocument := []byte("attestation-document")

	gotProvider, err := NewWithAttestation(
		context.Background(),
		newConstructorTestConfig(),
		aws.Config{},
		wantDocument,
	)

	require.NoError(t, err)
	got, ok := gotProvider.(*provider)
	require.True(t, ok)
	require.NotNil(t, got.recipient)
	require.Equal(t, wantDocument, got.recipient.AttestationDocument)
	require.Equal(t, types.KeyEncryptionMechanismRsaesOaepSha256, got.recipient.KeyEncryptionAlgorithm)
}

func TestNewForDevelopment_OmitsRecipientInfo(t *testing.T) {
	gotProvider, err := NewForDevelopment(
		context.Background(),
		newConstructorTestConfig(),
		aws.Config{},
	)

	require.NoError(t, err)
	got, ok := gotProvider.(*provider)
	require.True(t, ok)
	require.Nil(t, got.recipient)
}

func TestCall_FirstClientSuccess(t *testing.T) {
	first := newTestClient(t, "arn:aws:kms:us-east-1:123456789012:key/first")
	p := &provider{
		clients: []*client{first},
	}

	err := p.call(func(gotClient *client) error {
		require.Same(t, first, gotClient)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, p.clients, 1)
	require.Same(t, first, p.clients[0])
}

func TestCall_PartialFailureFallback(t *testing.T) {
	first := newTestClient(t, "arn:aws:kms:us-east-1:123456789012:key/first")
	second := newTestClient(t, "arn:aws:kms:us-west-2:123456789012:key/second")
	p := &provider{
		clients: []*client{first, second},
	}

	firstErr := errors.New("first client failed")
	var callOrder []*client
	err := p.call(func(gotClient *client) error {
		callOrder = append(callOrder, gotClient)
		if gotClient == first {
			return firstErr
		}
		require.Same(t, second, gotClient)
		return nil
	})

	require.NoError(t, err)
	require.Equal(t, []*client{first, second}, callOrder)
	require.Len(t, p.clients, 2)
	require.Same(t, second, p.clients[0])
	require.Same(t, first, p.clients[1])
}

func TestCall_AllClientsFail(t *testing.T) {
	first := newTestClient(t, "arn:aws:kms:us-east-1:123456789012:key/first")
	second := newTestClient(t, "arn:aws:kms:us-west-2:123456789012:key/second")
	p := &provider{
		clients: []*client{first, second},
	}

	firstErr := errors.New("first client failed")
	lastErr := errors.New("last client failed")
	err := p.call(func(gotClient *client) error {
		if gotClient == first {
			return firstErr
		}
		require.Same(t, second, gotClient)
		return lastErr
	})

	require.Error(t, err)
	require.ErrorContains(t, err, "all multi-region keys are invalid")
	require.ErrorIs(t, err, lastErr)
}

func TestDecrypt_EmptyCiphertext(t *testing.T) {
	tests := []struct {
		name       string
		ciphertext []byte
	}{
		{
			name:       "nil ciphertext",
			ciphertext: nil,
		},
		{
			name:       "empty ciphertext",
			ciphertext: []byte{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			p := &provider{
				clients: []*client{
					newTestClient(t, "arn:aws:kms:us-east-1:123456789012:key/test"),
				},
			}

			var (
				plaintext              []byte
				ciphertextForRecipient []byte
				err                    error
			)
			require.NotPanics(t, func() {
				plaintext, ciphertextForRecipient, err = p.Decrypt(context.Background(), tt.ciphertext)
			})

			require.EqualError(t, err, "invalid ciphertext")
			require.Nil(t, plaintext)
			require.Nil(t, ciphertextForRecipient)
		})
	}
}

func TestExtractRegionFromKmsKeyArn_ValidArn(t *testing.T) {
	region, err := extractRegionFromKmsKeyArn("arn:aws:kms:us-east-1:123456789012:key/1234abcd")

	require.NoError(t, err)
	require.Equal(t, "us-east-1", region)
}

func TestExtractRegionFromKmsKeyArn_MalformedArn(t *testing.T) {
	region, err := extractRegionFromKmsKeyArn("not-an-arn")

	require.Error(t, err)
	require.Empty(t, region)
}

func TestExtractRegionFromKmsKeyArn_RejectsNonKMSArn(t *testing.T) {
	region, err := extractRegionFromKmsKeyArn("arn:aws:s3:::my-bucket")

	require.Error(t, err)
	require.Empty(t, region)
}

func TestExtractRegionFromKmsKeyArn_RejectsNonAWSPartition(t *testing.T) {
	region, err := extractRegionFromKmsKeyArn(
		"arn:aws-cn:kms:cn-north-1:123456789012:key/1234abcd",
	)

	require.Error(t, err)
	require.Empty(t, region)
}

func TestExtractRegionFromKmsKeyArn_RejectsAuthorityInjection(t *testing.T) {
	region, err := extractRegionFromKmsKeyArn(
		"arn:aws:kms:@attackerdomain.com#:123456789012:key/1234abcd",
	)

	require.Error(t, err)
	require.Empty(t, region)
}

func TestValidateKMSRegion_RejectsInvalidSyntax(t *testing.T) {
	tests := map[string]string{
		"empty":             "",
		"at sign":           "us@east-1",
		"fragment":          "us#east-1",
		"slash":             "us/east-1",
		"query":             "us?east-1",
		"percent":           "us%east-1",
		"colon":             "us:east-1",
		"period":            "us.east-1",
		"space":             "us east-1",
		"control":           "us\neast-1",
		"uppercase":         "US-east-1",
		"non-ASCII":         "us-éast-1",
		"leading hyphen":    "-us-east-1",
		"trailing hyphen":   "us-east-1-",
		"longer than label": strings.Repeat("a", 64),
	}

	for name, region := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateKMSRegion(region)
			require.Error(t, err)
		})
	}
}

func TestValidateKMSRegion_AcceptsDNSLabel(t *testing.T) {
	tests := []string{
		"us-east-1",
		"us-gov-west-1",
		"a",
		strings.Repeat("a", 63),
	}

	for _, region := range tests {
		require.NoError(t, validateKMSRegion(region))
	}
}

func TestCanonicalKMSEndpoint_ReturnsExpectedURL(t *testing.T) {
	endpoint, err := canonicalKMSEndpoint("us-west-2")

	require.NoError(t, err)
	require.Equal(t, "https", endpoint.Scheme)
	require.Nil(t, endpoint.User)
	require.Empty(t, endpoint.Fragment)
	require.Equal(t, "kms.us-west-2.amazonaws.com", endpoint.Hostname())
	require.Equal(t, "https://kms.us-west-2.amazonaws.com", endpoint.String())
}

func TestInitClients_EmptyArns(t *testing.T) {
	clients, err := initClients(aws.Config{}, nil, 0, "")

	require.Error(t, err)
	require.Nil(t, clients)
}

func TestInitClients_InvalidArn(t *testing.T) {
	clients, err := initClients(aws.Config{}, []string{"bad-arn"}, 0, "")

	require.Error(t, err)
	require.ErrorContains(t, err, "invalid arn")
	require.Nil(t, clients)
}

func TestInitClients_StandardAWSPinsCanonicalEndpoint(t *testing.T) {
	clients, err := initClients(
		aws.Config{},
		[]string{"arn:aws:kms:us-west-2:123456789012:key/1234abcd"},
		time.Second,
		"http://127.0.0.1:9000",
	)

	require.NoError(t, err)
	require.Len(t, clients, 1)
	options := clients[0].Options()
	require.NotNil(t, options.BaseEndpoint)
	require.Equal(t, "https://kms.us-west-2.amazonaws.com", *options.BaseEndpoint)
	httpClient, ok := options.HTTPClient.(*awshttp.BuildableClient)
	require.True(t, ok)
	transport := httpClient.GetTransport()
	require.NotNil(t, transport.TLSClientConfig)
	require.Equal(t, "kms.us-west-2.amazonaws.com", transport.TLSClientConfig.ServerName)
}

func TestInitClients_LocalStackPreservesEndpointWithoutTLSPinning(t *testing.T) {
	localstackEndpoint := "http://127.0.0.1:4566"
	clients, err := initClients(
		aws.Config{BaseEndpoint: aws.String(localstackEndpoint)},
		[]string{"arn:aws:kms:us-west-2:123456789012:key/1234abcd"},
		0,
		"http://127.0.0.1:9000",
	)

	require.NoError(t, err)
	require.Len(t, clients, 1)
	options := clients[0].Options()
	require.NotNil(t, options.BaseEndpoint)
	require.Equal(t, localstackEndpoint, *options.BaseEndpoint)
	httpClient, ok := options.HTTPClient.(*awshttp.BuildableClient)
	require.True(t, ok)
	transport := httpClient.GetTransport()
	if transport.TLSClientConfig != nil {
		require.Empty(t, transport.TLSClientConfig.ServerName)
	}
}

func TestInitClientsRoutesEachARNRegion(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	arns := []string{
		"arn:aws:kms:us-east-1:123456789012:key/first",
		"arn:aws:kms:us-west-2:123456789012:key/second",
	}
	clients, err := initClients(aws.Config{}, arns, 0, "http://"+ln.Addr().String())
	require.NoError(t, err)
	require.Len(t, clients, 2)

	for i, wantRegion := range []string{"us-east-1", "us-west-2"} {
		httpClient, ok := clients[i].Options().HTTPClient.(*awshttp.BuildableClient)
		require.True(t, ok)
		conn, dialErr := httpClient.GetTransport().DialContext(
			context.Background(), "tcp", "kms."+wantRegion+".amazonaws.com:443",
		)
		require.NoError(t, dialErr)
		t.Cleanup(func() { _ = conn.Close() })

		accepted, acceptErr := ln.Accept()
		require.NoError(t, acceptErr)
		route, routeErr := byteproxy.ReadAWSRoute(accepted)
		require.NoError(t, routeErr)
		require.NoError(t, accepted.Close())
		require.Equal(t, byteproxy.AWSRoute{Service: "kms", Region: wantRegion}, route)
	}
}
