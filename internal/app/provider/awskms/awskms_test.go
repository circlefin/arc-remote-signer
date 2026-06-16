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
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, arn string) *client {
	t.Helper()
	return &client{arn: arn}
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

func TestInitClients_EmptyArns(t *testing.T) {
	clients, err := initClients(aws.Config{}, nil, 0)

	require.Error(t, err)
	require.Nil(t, clients)
}

func TestInitClients_InvalidArn(t *testing.T) {
	clients, err := initClients(aws.Config{}, []string{"bad-arn"}, 0)

	require.Error(t, err)
	require.ErrorContains(t, err, "invalid arn")
	require.Nil(t, clients)
}
