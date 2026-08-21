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

// Package awskms is the enclave-side AWS KMS provider. It owns the KMS
// Provider interface and implementation (New, Decrypt, GenerateDataKey), the
// aws.Config builder the enclave Initialize handler uses to construct an
// ephemeral client, the Factory seam, and the error-to-gRPC-status mapping.
package awskms

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
	"github.com/circlefin/arc-remote-signer/proto/pb"
)

// BuildConfig constructs an aws.Config for use inside the enclave
// during Initialize. Credentials come from the host-supplied request.
//
// awsproxyEndpoint is where the SDK's TCP dial gets redirected to (the
// in-enclave awsproxy listener).
//
// localstackEnabled makes the SDK use awsproxyEndpoint as its base endpoint
// over plain HTTP. Standard AWS KMS keeps the natural AWS endpoint and uses
// end-to-end TLS.
//
// BuildConfig validates creds.Region before it adds the region to the config.
// The enclave-side initClients also validates each ARN region. It gives each
// KMS client a routed HTTP transport.
func BuildConfig(creds *pb.AwsCredentials, awsproxyEndpoint string, localstackEnabled bool) (aws.Config, error) {
	if creds == nil {
		return aws.Config{}, errors.New("nil credentials")
	}
	if err := validateKMSRegion(creds.Region); err != nil {
		return aws.Config{}, fmt.Errorf("%w: credentials region: %w", ErrInvalidRegion, err)
	}
	if awsproxyEndpoint == "" {
		return aws.Config{}, errors.New("empty awsproxy endpoint")
	}
	httpClient, err := newAwsproxyHTTPClient(awsproxyEndpoint, nil, "")
	if err != nil {
		return aws.Config{}, fmt.Errorf("build awsproxy http client: %w", err)
	}
	cfg := aws.Config{
		Region: creds.Region,
		Credentials: credentials.NewStaticCredentialsProvider(
			creds.AccessKeyId,
			creds.SecretAccessKey,
			creds.SessionToken,
		),
		HTTPClient: httpClient,
	}
	if localstackEnabled {
		cfg.BaseEndpoint = aws.String(awsproxyEndpoint)
	}
	return cfg, nil
}

// newAwsproxyHTTPClient returns a client whose Transport redirects every TCP
// dial to awsproxy while leaving the SDK's endpoint view intact. A non-nil
// route is written before the SDK stream. BuildConfig leaves it nil for direct
// LocalStack use; production initClients replaces it with per-ARN routes.
//
// It builds on awshttp.BuildableClient rather than a bare *http.Client so
// the SDK's per-request timeout (awskms.WithTimeout) and DefaultsMode
// dial/TLS timeouts still attach — those only apply when HTTPClient is a
// *awshttp.BuildableClient; a plain *http.Client silently drops them.
func newAwsproxyHTTPClient(
	awsproxyEndpoint string,
	route *byteproxy.AWSRoute,
	tlsServerName string,
) (*awshttp.BuildableClient, error) {
	u, err := url.Parse(awsproxyEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parse awsproxy endpoint %q: %w", awsproxyEndpoint, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("awsproxy endpoint %q has no host", awsproxyEndpoint)
	}
	// A non-empty Host does not guarantee a port; net.Dialer needs host:port,
	// so reject a portless endpoint here rather than failing later with an
	// opaque "missing port in address" at dial time.
	if u.Port() == "" {
		return nil, fmt.Errorf("awsproxy endpoint %q has no port", awsproxyEndpoint)
	}
	proxyAddr := u.Host
	return awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
		if tlsServerName != "" {
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			} else {
				tr.TLSClientConfig = tr.TLSClientConfig.Clone()
			}
			tr.TLSClientConfig.ServerName = tlsServerName
		}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, proxyAddr)
			if err != nil {
				return nil, err
			}
			if route != nil {
				if err := byteproxy.WriteAWSRoute(conn, *route); err != nil {
					_ = conn.Close()
					return nil, fmt.Errorf("write awsproxy route: %w", err)
				}
			}
			return conn, nil
		}
	}), nil
}
