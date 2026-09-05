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
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type kmsHTTPClientFunc func(*http.Request) (*http.Response, error)

func (f kmsHTTPClientFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newGenerateDataKeyTestClient(
	region string,
	do kmsHTTPClientFunc,
) *client {
	arn := "arn:aws:kms:" + region + ":123456789012:key/test"
	sdkClient := kms.New(kms.Options{
		Credentials: aws.AnonymousCredentials{},
		HTTPClient:  do,
		Region:      region,
		Retryer:     aws.NopRetryer{},
	})
	return &client{Client: sdkClient, arn: arn}
}

func generateDataKeyResponse(req *http.Request) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/x-amz-json-1.1"},
		},
		Body: io.NopCloser(strings.NewReader(
			`{"Plaintext":"cGxhaW50ZXh0","CiphertextBlob":"Y2lwaGVydGV4dA=="}`,
		)),
		Request: req,
	}
}

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

func expiredTokenError() error {
	return &smithy.GenericAPIError{Code: "ExpiredTokenException", Message: "security token expired"}
}

func transportFailureError() error {
	return &url.Error{
		Op:  "Post",
		URL: "https://kms.us-west-2.amazonaws.com",
		Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")},
	}
}

func requireExpiredTokenUnauthenticated(t *testing.T, err error) {
	t.Helper()
	var apiErr smithy.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, "ExpiredTokenException", apiErr.ErrorCode())
	mapped := StatusFromError(err)
	st, ok := status.FromError(mapped)
	require.True(t, ok)
	require.Equal(t, codes.Unauthenticated, st.Code())
}

func TestCall_PreservesExpiredTokenOverLaterTransportFailure(t *testing.T) {
	first := newTestClient(t, "arn:aws:kms:us-east-1:123456789012:key/first")
	second := newTestClient(t, "arn:aws:kms:us-west-2:123456789012:key/second")
	p := &provider{
		clients: []*client{first, second},
	}

	firstErr := expiredTokenError()
	var callOrder []*client
	err := p.call(func(gotClient *client) error {
		callOrder = append(callOrder, gotClient)
		if gotClient == first {
			return firstErr
		}
		require.Same(t, second, gotClient)
		return transportFailureError()
	})

	require.Equal(t, []*client{first, second}, callOrder)
	require.ErrorContains(t, err, "all multi-region keys are invalid")
	requireExpiredTokenUnauthenticated(t, err)
}

func TestGenerateDataKey_FailsOverAfterFirstRegionTimeoutOrThrottle(t *testing.T) {
	tests := map[string]error{
		"timeout":    context.DeadlineExceeded,
		"throttling": &smithy.GenericAPIError{Code: "ThrottlingException", Message: "rate exceeded"},
	}

	for name, firstRegionErr := range tests {
		t.Run(name, func(t *testing.T) {
			var callOrder []string
			first := newGenerateDataKeyTestClient(
				"us-east-1",
				func(*http.Request) (*http.Response, error) {
					callOrder = append(callOrder, "us-east-1")
					return nil, firstRegionErr
				},
			)
			second := newGenerateDataKeyTestClient(
				"us-west-2",
				func(req *http.Request) (*http.Response, error) {
					callOrder = append(callOrder, "us-west-2")
					return generateDataKeyResponse(req), nil
				},
			)
			p := &provider{clients: []*client{first, second}}

			plaintext, ciphertext, _, err := p.GenerateDataKey(context.Background())

			require.NoError(t, err)
			require.Equal(t, []byte("plaintext"), plaintext)
			require.Equal(t, []byte("ciphertext"), ciphertext)
			require.Equal(t, []string{"us-east-1", "us-west-2"}, callOrder)
		})
	}
}

func TestGenerateDataKey_AllRegionsTimeout(t *testing.T) {
	var callOrder []string
	timeoutClient := func(region string) *client {
		return newGenerateDataKeyTestClient(
			region,
			func(*http.Request) (*http.Response, error) {
				callOrder = append(callOrder, region)
				return nil, context.DeadlineExceeded
			},
		)
	}
	p := &provider{clients: []*client{
		timeoutClient("us-east-1"),
		timeoutClient("us-west-2"),
	}}

	_, _, _, err := p.GenerateDataKey(context.Background())

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, []string{"us-east-1", "us-west-2"}, callOrder)
}

func TestGenerateDataKey_PreservesExpiredTokenOverLaterTransportFailure(t *testing.T) {
	var callOrder []string
	first := newGenerateDataKeyTestClient(
		"us-east-1",
		func(*http.Request) (*http.Response, error) {
			callOrder = append(callOrder, "us-east-1")
			return nil, expiredTokenError()
		},
	)
	second := newGenerateDataKeyTestClient(
		"us-west-2",
		func(*http.Request) (*http.Response, error) {
			callOrder = append(callOrder, "us-west-2")
			return nil, transportFailureError()
		},
	)
	p := &provider{clients: []*client{first, second}}

	_, _, _, err := p.GenerateDataKey(context.Background())

	require.Equal(t, []string{"us-east-1", "us-west-2"}, callOrder)
	requireExpiredTokenUnauthenticated(t, err)
}

func TestGenerateDataKey_PrefersExpiredTokenOverEarlierTimeout(t *testing.T) {
	var callOrder []string
	first := newGenerateDataKeyTestClient(
		"us-east-1",
		func(*http.Request) (*http.Response, error) {
			callOrder = append(callOrder, "us-east-1")
			return nil, context.DeadlineExceeded
		},
	)
	second := newGenerateDataKeyTestClient(
		"us-west-2",
		func(*http.Request) (*http.Response, error) {
			callOrder = append(callOrder, "us-west-2")
			return nil, expiredTokenError()
		},
	)
	p := &provider{clients: []*client{first, second}}

	_, _, _, err := p.GenerateDataKey(context.Background())

	require.Equal(t, []string{"us-east-1", "us-west-2"}, callOrder)
	requireExpiredTokenUnauthenticated(t, err)
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

func TestExtractRegionFromKmsKeyArn_RejectsUnsupportedRegion(t *testing.T) {
	region, err := extractRegionFromKmsKeyArn(
		"arn:aws:kms:s3:123456789012:key/1234abcd",
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

func TestValidateKMSRegion_AcceptsCommercialKMSRegions(t *testing.T) {
	tests := []string{
		"af-south-1",
		"ap-east-1",
		"ap-east-2",
		"ap-northeast-1",
		"ap-northeast-2",
		"ap-northeast-3",
		"ap-south-1",
		"ap-south-2",
		"ap-southeast-1",
		"ap-southeast-2",
		"ap-southeast-3",
		"ap-southeast-4",
		"ap-southeast-5",
		"ap-southeast-6",
		"ap-southeast-7",
		"ca-central-1",
		"ca-west-1",
		"eu-central-1",
		"eu-central-2",
		"eu-north-1",
		"eu-south-1",
		"eu-south-2",
		"eu-west-1",
		"eu-west-2",
		"eu-west-3",
		"il-central-1",
		"me-central-1",
		"me-south-1",
		"mx-central-1",
		"sa-east-1",
		"us-east-1",
		"us-east-2",
		"us-west-1",
		"us-west-2",
	}

	for _, region := range tests {
		t.Run(region, func(t *testing.T) {
			require.NoError(t, validateKMSRegion(region))
		})
	}
}

func TestValidateKMSRegion_RejectsUnsupportedRegions(t *testing.T) {
	tests := []string{
		"s3",
		"a",
		strings.Repeat("a", 63),
		"us-mars-1",
		"us-gov-west-1",
		"cn-north-1",
	}

	for _, region := range tests {
		t.Run(region, func(t *testing.T) {
			require.Error(t, validateKMSRegion(region))
		})
	}
}

func TestValidateRegions(t *testing.T) {
	tests := []struct {
		name              string
		credentialsRegion string
		arns              []string
		wantErr           error
	}{
		{
			name:              "valid credentials and ARN regions",
			credentialsRegion: "us-east-1",
			arns:              []string{"arn:aws:kms:us-west-2:123456789012:key/test"},
		},
		{
			name:              "invalid credentials region",
			credentialsRegion: "s3",
			arns:              []string{"arn:aws:kms:us-west-2:123456789012:key/test"},
			wantErr:           ErrInvalidRegion,
		},
		{
			name:              "invalid ARN region",
			credentialsRegion: "us-east-1",
			arns:              []string{"arn:aws:kms:s3:123456789012:key/test"},
			wantErr:           ErrInvalidARN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRegions(tt.credentialsRegion, tt.arns)
			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.wantErr)
		})
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

func TestInitClients_RejectsUnsupportedRegion(t *testing.T) {
	clients, err := initClients(
		aws.Config{},
		[]string{"arn:aws:kms:s3:123456789012:key/1234abcd"},
		0,
		"",
	)

	require.Error(t, err)
	require.ErrorContains(t, err, "invalid arn_1")
	require.Nil(t, clients)
}

func TestInitClients_ValidatesAllARNsBeforeConstructingClients(t *testing.T) {
	clients, err := initClients(
		aws.Config{},
		[]string{
			"arn:aws:kms:us-east-1:123456789012:key/first",
			"arn:aws:kms:s3:123456789012:key/second",
		},
		0,
		"://invalid-proxy-endpoint",
	)

	require.ErrorIs(t, err, ErrInvalidARN)
	require.ErrorContains(t, err, "invalid arn_2")
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
	require.NotNil(t, transport.TLSClientConfig.RootCAs)
}

func TestInitClients_DisablesKeepAlivesForAttemptScopedClients(t *testing.T) {
	clients, err := initClients(
		aws.Config{},
		[]string{"arn:aws:kms:us-west-2:123456789012:key/1234abcd"},
		time.Second,
		"http://127.0.0.1:9000",
	)

	require.NoError(t, err)
	require.Len(t, clients, 1)
	options := clients[0].Options()
	httpClient, ok := options.HTTPClient.(*awshttp.BuildableClient)
	require.True(t, ok)
	require.True(t, httpClient.GetTransport().DisableKeepAlives)
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
