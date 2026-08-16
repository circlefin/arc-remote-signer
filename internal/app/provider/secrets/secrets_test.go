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

package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockSecretsClient struct {
	getSecretValueFunc func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	putSecretValueFunc func(ctx context.Context, params *secretsmanager.PutSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
}

func (m *mockSecretsClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if m.getSecretValueFunc != nil {
		return m.getSecretValueFunc(ctx, params, optFns...)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretsClient) PutSecretValue(ctx context.Context, params *secretsmanager.PutSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	if m.putSecretValueFunc != nil {
		return m.putSecretValueFunc(ctx, params, optFns...)
	}
	return nil, errors.New("not implemented")
}

func TestProviderImpl_Get_SecretString(t *testing.T) {
	rawSecret := []byte("hello-secret-world")
	encoded := base64.StdEncoding.EncodeToString(rawSecret)

	mockClient := &mockSecretsClient{
		getSecretValueFunc: func(_ context.Context, params *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			require.Equal(t, "my-secret-id", aws.ToString(params.SecretId))
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String(encoded),
			}, nil
		},
	}

	provider := &ProviderImpl{secretClient: mockClient}
	secret, err := provider.Get(context.Background(), "my-secret-id")
	require.NoError(t, err)
	require.Equal(t, rawSecret, secret)
}

func TestProviderImpl_Get_SecretBinary(t *testing.T) {
	rawSecret := []byte("binary-secret-bytes")

	mockClient := &mockSecretsClient{
		getSecretValueFunc: func(_ context.Context, params *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			require.Equal(t, "bin-secret-id", aws.ToString(params.SecretId))
			return &secretsmanager.GetSecretValueOutput{
				SecretBinary: rawSecret,
			}, nil
		},
	}

	provider := &ProviderImpl{secretClient: mockClient}
	secret, err := provider.Get(context.Background(), "bin-secret-id")
	require.NoError(t, err)
	require.Equal(t, rawSecret, secret)
}

func TestProviderImpl_Get_ResourceNotFound(t *testing.T) {
	mockClient := &mockSecretsClient{
		getSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, &types.ResourceNotFoundException{
				Message: aws.String("Resource not found"),
			}
		},
	}

	provider := &ProviderImpl{secretClient: mockClient}
	secret, err := provider.Get(context.Background(), "non-existent-secret")
	require.NoError(t, err)
	require.Nil(t, secret)
}

func TestProviderImpl_Get_NilFields(t *testing.T) {
	mockClient := &mockSecretsClient{
		getSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: nil,
				SecretBinary: nil,
			}, nil
		},
	}

	provider := &ProviderImpl{secretClient: mockClient}
	secret, err := provider.Get(context.Background(), "empty-secret")
	require.NoError(t, err)
	require.Nil(t, secret)
}

func TestProviderImpl_Get_Error(t *testing.T) {
	mockClient := &mockSecretsClient{
		getSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	provider := &ProviderImpl{secretClient: mockClient}
	secret, err := provider.Get(context.Background(), "error-secret")
	require.Error(t, err)
	require.Nil(t, secret)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Internal, st.Code())
	require.Contains(t, st.Message(), "failed to get secret: access denied")
}

func TestProviderImpl_Update_Success(t *testing.T) {
	rawSecret := []byte("update-payload")
	expectedArn := "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret"

	mockClient := &mockSecretsClient{
		putSecretValueFunc: func(_ context.Context, params *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
			require.Equal(t, "my-secret-id", aws.ToString(params.SecretId))
			require.Equal(t, base64.StdEncoding.EncodeToString(rawSecret), aws.ToString(params.SecretString))
			return &secretsmanager.PutSecretValueOutput{
				ARN: aws.String(expectedArn),
			}, nil
		},
	}

	provider := &ProviderImpl{secretClient: mockClient}
	arn, err := provider.Update(context.Background(), "my-secret-id", rawSecret)
	require.NoError(t, err)
	require.Equal(t, expectedArn, arn)
}

func TestProviderImpl_Update_NilARN(t *testing.T) {
	rawSecret := []byte("update-payload")

	mockClient := &mockSecretsClient{
		putSecretValueFunc: func(_ context.Context, _ *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
			return &secretsmanager.PutSecretValueOutput{
				ARN: nil,
			}, nil
		},
	}

	provider := &ProviderImpl{secretClient: mockClient}
	arn, err := provider.Update(context.Background(), "my-secret-id", rawSecret)
	require.NoError(t, err)
	require.Empty(t, arn)
}

func TestProviderImpl_Update_Error(t *testing.T) {
	mockClient := &mockSecretsClient{
		putSecretValueFunc: func(_ context.Context, _ *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
			return nil, errors.New("kms key unavailable")
		},
	}

	provider := &ProviderImpl{secretClient: mockClient}
	arn, err := provider.Update(context.Background(), "error-secret", []byte("payload"))
	require.Error(t, err)
	require.Empty(t, arn)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Internal, st.Code())
	require.Contains(t, st.Message(), "failed to update secret: kms key unavailable")
}
