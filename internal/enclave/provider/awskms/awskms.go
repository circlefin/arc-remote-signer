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

//go:generate mockgen -source=awskms.go -destination=awskms_mock.go -package=awskms

package awskms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/circlefin/arc-remote-signer/internal/common/byteproxy"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
)

var _logger *logging.Logger

func getLogger() *logging.Logger {
	if _logger != nil {
		return _logger
	}
	_logger = logging.Get("awskms.provider")
	return _logger
}

// ErrInvalidARN marks a configured KMS ARN that is syntactically parseable but
// not a usable KMS key ARN (wrong service or missing region). The enclave
// service maps this class of error to codes.InvalidArgument.
var ErrInvalidARN = errors.New("invalid kms key arn")

// ErrInvalidRegion marks a host-supplied AWS region that fails validation.
// The enclave service maps this error to codes.InvalidArgument.
var ErrInvalidRegion = errors.New("invalid AWS region")

// ErrAttestationDocumentRequired marks an attempt to construct a Nitro KMS
// provider without an enclave attestation document.
var ErrAttestationDocumentRequired = errors.New("attestation document is required in Nitro mode")

// Provider is the interface for the aws kms provider.
type Provider interface {
	Decrypt(ctx context.Context, ciphertext []byte) (plaintext []byte, ciphertextForRecipient []byte, err error)
	GenerateDataKey(ctx context.Context) (plainDataKey []byte, cipherDataKey []byte, ciphertextForRecipient []byte, err error)
}

type client struct {
	*kms.Client
	arn string
}

// provider implement the method of Provider interface and communicate with AWS KMS.
type provider struct {
	clients   []*client
	recipient *types.RecipientInfo

	mu sync.Mutex
}

// NewWithAttestation constructs a provider that asks KMS to encrypt data keys
// for the attested enclave.
func NewWithAttestation(
	ctx context.Context,
	cfg *Config,
	awsCfg aws.Config,
	attestationDocument []byte,
) (Provider, error) {
	if len(attestationDocument) == 0 {
		return nil, ErrAttestationDocumentRequired
	}

	return newProvider(ctx, cfg, awsCfg, &types.RecipientInfo{
		AttestationDocument:    attestationDocument,
		KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
	})
}

// NewForDevelopment constructs a provider for development environments where
// KMS returns plaintext data keys without enclave attestation.
func NewForDevelopment(ctx context.Context, cfg *Config, awsCfg aws.Config) (Provider, error) {
	return newProvider(ctx, cfg, awsCfg, nil)
}

func newProvider(
	ctx context.Context,
	cfg *Config,
	awsCfg aws.Config,
	recipient *types.RecipientInfo,
) (Provider, error) {
	clients, err := initClients(
		awsCfg,
		cfg.Arns,
		time.Duration(cfg.ConnectTimeout)*time.Millisecond,
		cfg.AwsproxyEndpoint,
	)
	if err != nil {
		getLogger().WarnErr(ctx, "initClients failed", err, nil)
		return nil, err
	}

	provider := &provider{
		clients:   clients,
		recipient: recipient,
	}
	return provider, nil
}

func (p *provider) moveClientToBack(c *client) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, v := range p.clients {
		if v == c {
			p.clients = append(append(p.clients[:i], p.clients[i+1:]...), v)
			return
		}
	}
}

func (p *provider) call(fn func(*client) error) error {
	p.mu.Lock()
	clients := make([]*client, len(p.clients))
	copy(clients, p.clients)
	p.mu.Unlock()
	var err error
	var authErr error
	for _, client := range clients {
		err = fn(client)
		if err == nil {
			return nil
		}
		if authErr == nil {
			authErr = credentialAuthError(err)
		}
		p.moveClientToBack(client)
	}
	if authErr != nil {
		err = authErr
	}
	return fmt.Errorf("all multi-region keys are invalid, error: %w", err)
}

// Decrypt will decrypt ciphertext with kms symmetry key and return the plaintext.
// If the recipient is not nil, it will use the recipient to decrypt the ciphertext and return the ciphertext for recipient as well.
func (p *provider) Decrypt(ctx context.Context, ciphertext []byte) (plaintext []byte, ciphertextForRecipient []byte, err error) {
	if len(ciphertext) == 0 {
		return nil, nil, errors.New("invalid ciphertext")
	}
	var res *kms.DecryptOutput
	err = p.call(func(client *client) error {
		input := &kms.DecryptInput{
			KeyId:          &client.arn,
			CiphertextBlob: ciphertext,
			Recipient:      p.recipient,
		}
		res, err = client.Decrypt(ctx, input)
		if err != nil {
			getLogger().WarnErr(ctx, "p.client.Decrypt failed", err, logging.Entries{"arn": client.arn})
			return err
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return res.Plaintext, res.CiphertextForRecipient, nil
}

// GenerateDataKey will call aws kms to generate a new data key, and return its ciphertext and plaintext. If there is error, it's will failover to next region until all clients fail.
// If the recipient is not nil, it will use the recipient to generate the data key and return the ciphertext for recipient as well.
func (p *provider) GenerateDataKey(ctx context.Context) (plainDataKey, cipherDataKey, ciphertextForRecipient []byte, err error) {
	var res *kms.GenerateDataKeyOutput
	err = p.call(func(client *client) error {
		input := &kms.GenerateDataKeyInput{
			KeyId:     &client.arn,
			KeySpec:   types.DataKeySpecAes256,
			Recipient: p.recipient,
		}
		res, err = client.GenerateDataKey(ctx, input)
		if err != nil {
			getLogger().WarnErr(ctx, "p.client.GenerateDataKey failed", err, logging.Entries{"arn": client.arn})
			return err
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return res.Plaintext, res.CiphertextBlob, res.CiphertextForRecipient, nil
}

// initClients will create a clients slice for each valid ARN and return if there is an invalid arn.
func initClients(
	cfg aws.Config,
	arns []string,
	timeout time.Duration,
	awsproxyEndpoint string,
) (clients []*client, err error) {
	regions, err := validateKMSKeyARNs(arns)
	if err != nil {
		return nil, err
	}

	var opts []func(*kms.Options)
	if timeout > 0 {
		// The following code implements behavior similar to the default setting in aws-sdk-go-v2.
		// The key modification is that we set MaxBackoff to 300ms, whereas the default value is 20s,
		// which is significantly longer than our latency alert threshold.
		customRetryer := retry.NewStandard(func(o *retry.StandardOptions) {
			o.MaxBackoff = time.Millisecond * 300
			o.Retryables = append(o.Retryables, retry.RetryableHTTPStatusCode{
				Codes: map[int]struct{}{
					http.StatusTooManyRequests: {},
				},
			})
		})
		opts = append(opts, func(o *kms.Options) { o.Retryer = customRetryer })
		opts = append(opts, WithTimeout(timeout))
	}

	for i, arn := range arns {
		region := regions[i]
		c := cfg.Copy()
		c.Region = region
		var tlsServerName string
		if c.BaseEndpoint == nil {
			endpoint, err := canonicalKMSEndpoint(region)
			if err != nil {
				return nil, fmt.Errorf("build KMS endpoint for arn_%d: %w", i+1, err)
			}
			c.BaseEndpoint = aws.String(endpoint.String())
			tlsServerName = endpoint.Hostname()
		}
		if awsproxyEndpoint != "" {
			route := byteproxy.AWSRoute{
				Service: "kms",
				Region:  region,
			}
			httpClient, err := newAwsproxyHTTPClient(awsproxyEndpoint, &route, tlsServerName)
			if err != nil {
				return nil, fmt.Errorf("build awsproxy HTTP client for arn_%d: %w", i+1, err)
			}
			httpClient = httpClient.WithTransportOptions(func(tr *http.Transport) {
				tr.DisableKeepAlives = true
			})
			c.HTTPClient = httpClient
		}
		clients = append(clients, &client{
			Client: kms.NewFromConfig(c, opts...),
			arn:    arn,
		})
	}
	return clients, nil
}

// ValidateRegions checks every host-supplied region used during enclave KMS
// initialization without constructing AWS endpoints, routes, or SDK clients.
func ValidateRegions(credentialsRegion string, arns []string) error {
	if err := validateCredentialsRegion(credentialsRegion); err != nil {
		return err
	}
	_, err := validateKMSKeyARNs(arns)
	return err
}

func validateKMSKeyARNs(arns []string) ([]string, error) {
	if len(arns) == 0 {
		return nil, errors.New("there is no arn")
	}

	regions := make([]string, len(arns))
	for i, arn := range arns {
		region, err := extractRegionFromKmsKeyArn(arn)
		if err != nil {
			return nil, fmt.Errorf("invalid arn_%d: %w: %w", i+1, ErrInvalidARN, err)
		}
		regions[i] = region
	}
	return regions, nil
}

func extractRegionFromKmsKeyArn(arnStr string) (string, error) {
	arnObj, err := arn.Parse(arnStr)
	if err != nil {
		getLogger().WarnErr(context.Background(), "arn.Parse failed", err, nil)
		return "", err
	}
	if arnObj.Partition != "aws" {
		return "", fmt.Errorf("ARN partition %q is not supported", arnObj.Partition)
	}
	if arnObj.Service != "kms" {
		return "", fmt.Errorf("ARN service %q is not KMS", arnObj.Service)
	}
	if arnObj.Region == "" {
		return "", errors.New("KMS ARN has no region")
	}
	if err := validateKMSRegion(arnObj.Region); err != nil {
		return "", err
	}
	return arnObj.Region, nil
}

func validateKMSRegion(region string) error {
	// This list is the AWS commercial partition subset of KMS endpoints at
	// https://docs.aws.amazon.com/general/latest/gr/kms.html. Keep this switch and
	// TestValidateKMSRegion_AcceptsCommercialKMSRegions synchronized when AWS adds
	// a KMS region. GovCloud, China, and isolated partitions are not supported.
	switch region {
	case "af-south-1",
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
		"us-west-2":
		return nil
	default:
		return fmt.Errorf("KMS region %q is not supported", region)
	}
}

func canonicalKMSEndpoint(region string) (*url.URL, error) {
	if err := validateKMSRegion(region); err != nil {
		return nil, err
	}
	hostname := "kms." + region + ".amazonaws.com"
	endpoint, err := url.Parse("https://" + hostname)
	if err != nil {
		return nil, fmt.Errorf("parse canonical KMS endpoint: %w", err)
	}
	if endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Fragment != "" ||
		endpoint.Hostname() != hostname {
		return nil, errors.New("canonical KMS endpoint has invalid URL components")
	}
	return endpoint, nil
}

// WithTimeout returns a function that sets a custom timeout for the KMS client.
func WithTimeout(timeout time.Duration) func(*kms.Options) {
	return func(opts *kms.Options) {
		if cli, ok := opts.HTTPClient.(*awshttp.BuildableClient); ok && cli != nil {
			opts.HTTPClient = cli.WithTimeout(timeout)
		}
	}
}
