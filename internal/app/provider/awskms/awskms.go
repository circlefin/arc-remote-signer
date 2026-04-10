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

// Package awskms implement crypto provider interface.
package awskms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
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

// New function Init the provider with specific config and return the instance.
func New(ctx context.Context, cfg *Config, awsCfg aws.Config, attestationDocument []byte) (Provider, error) {
	clients, err := initClients(awsCfg, cfg.Arns, time.Duration(cfg.ConnectTimeout)*time.Millisecond)
	if err != nil {
		getLogger().WarnErr(ctx, "initClients failed", err, nil)
		return nil, err
	}

	var recipient *types.RecipientInfo
	if len(attestationDocument) > 0 {
		recipient = &types.RecipientInfo{
			AttestationDocument:    attestationDocument,
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
		}
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
	for _, client := range clients {
		err = fn(client)
		if err == nil {
			return nil
		}
		p.moveClientToBack(client)
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
func initClients(cfg aws.Config, arns []string, timeout time.Duration) (clients []*client, err error) {
	// precheck arns
	if len(arns) == 0 {
		return nil, errors.New("there is no arn")
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
		region, err := extractRegionFromKmsKeyArn(arn)
		if err != nil {
			return nil, fmt.Errorf("invalid arn(arn_%v))", i+1)
		}

		c := cfg.Copy()
		c.Region = region
		clients = append(clients, &client{
			Client: kms.NewFromConfig(c, opts...),
			arn:    arn,
		})
	}
	return clients, nil
}

func extractRegionFromKmsKeyArn(arnStr string) (string, error) {
	arnObj, err := arn.Parse(arnStr)
	if err != nil {
		getLogger().WarnErr(context.Background(), "arn.Parse failed", err, nil)
		return "", err
	}
	return arnObj.Region, nil
}

// WithTimeout returns a function that sets a custom timeout for the KMS client.
func WithTimeout(timeout time.Duration) func(*kms.Options) {
	return func(opts *kms.Options) {
		if cli, ok := opts.HTTPClient.(*awshttp.BuildableClient); ok && cli != nil {
			opts.HTTPClient = cli.WithTimeout(timeout)
		}
	}
}
