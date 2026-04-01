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

//go:generate mockgen -source=secrets.go -destination=secrets_mock.go -package=secrets

// Package secrets provides a secrets manager implementation for AWS Secrets Manager.
package secrets

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ Provider = (*ProviderImpl)(nil)

// Provider is the interface for the secrets provider.
type Provider interface {
	// Get retrieves a secret from AWS Secrets Manager.
	Get(ctx context.Context, secretID string) (secret []byte, err error)
	// Update updates a secret in AWS Secrets Manager.
	Update(ctx context.Context, secretID string, secret []byte) (string, error)
}

// ProviderImpl is the implementation of the secrets provider.
type ProviderImpl struct {
	secretClient *secretsmanager.Client
}

// New creates a new secrets provider.
func New(cfg aws.Config) *ProviderImpl {
	secretClient := secretsmanager.NewFromConfig(cfg)
	return &ProviderImpl{secretClient: secretClient}
}

// Get retrieves a secret from AWS Secrets Manager.
// If the secret is not found, it returns nil and no error.
func (p *ProviderImpl) Get(ctx context.Context, secretID string) (secret []byte, err error) {
	resp, err := p.secretClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		if temp := new(types.ResourceNotFoundException); errors.As(err, &temp) {
			return nil, nil
		}
		return nil, status.Errorf(codes.Internal, "failed to get secret: %v", err)
	}
	return base64.StdEncoding.DecodeString(*resp.SecretString)
}

// Update updates a secret in AWS Secrets Manager.
func (p *ProviderImpl) Update(ctx context.Context, secretID string, secret []byte) (string, error) {
	resp, err := p.secretClient.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(secretID),
		SecretString: aws.String(base64.StdEncoding.EncodeToString(secret)),
	})
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to update secret: %v", err)
	}
	return *resp.ARN, nil
}
