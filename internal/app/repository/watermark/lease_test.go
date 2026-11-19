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

package watermark

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/circlefin/arc-remote-signer/internal/common/replica"
	"github.com/stretchr/testify/require"
)

type failingLeaseClient struct {
	item                         map[string]types.AttributeValue
	readErr, writeErr, deleteErr error
}

func (c failingLeaseClient) GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	return &dynamodb.GetItemOutput{Item: c.item}, c.readErr
}
func (c failingLeaseClient) UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	return &dynamodb.UpdateItemOutput{}, c.writeErr
}
func (c failingLeaseClient) DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	return &dynamodb.DeleteItemOutput{}, c.deleteErr
}
func leaseTestID(t *testing.T) replica.ID {
	t.Helper()
	id, err := replica.NewID("a")
	require.NoError(t, err)
	return id
}

func TestLeaseRepositoryFailsClosedOnCorruptState(t *testing.T) {
	ctx := context.Background()
	name := leaseTestID(t)
	tests := []struct {
		name    string
		item    map[string]types.AttributeValue
		session bool
	}{
		{"holder missing session", map[string]types.AttributeValue{"holder": s("a"), "expires_at": n(200)}, false},
		{"holder missing expiry", map[string]types.AttributeValue{"holder": s("a"), "session_id": b([]byte("a"))}, false},
		{"orphan session", map[string]types.AttributeValue{"session_id": b([]byte("a"))}, false},
		{"revocation missing end", map[string]types.AttributeValue{"revoked_name": s("a")}, false},
		{"session missing progress", map[string]types.AttributeValue{"session_id": b([]byte("a")), "last_call_at": n(100)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := LeaseRepository{client: failingLeaseClient{item: tt.item}, tableName: TableName, validatorID: "test"}
			if tt.session {
				_, _, err := r.ReadSession(ctx, name)
				require.Error(t, err)
			} else {
				_, _, err := r.ReadLease(ctx)
				require.Error(t, err)
			}
		})
	}
}

func TestLeaseRepositoryPropagatesStorageFailures(t *testing.T) {
	ctx := context.Background()
	name := leaseTestID(t)
	sentinel := errors.New("storage unavailable")
	r := LeaseRepository{client: failingLeaseClient{readErr: sentinel}, tableName: TableName, validatorID: "test"}
	_, _, err := r.ReadLease(ctx)
	require.ErrorIs(t, err, sentinel)
	_, _, err = r.ReadSession(ctx, name)
	require.ErrorIs(t, err, sentinel)
	err = r.RecordCall(ctx, name, []byte("sid"), 1000, 100, 1)
	require.ErrorIs(t, err, sentinel)
	r.client = failingLeaseClient{writeErr: sentinel}
	_, err = r.Grant(ctx, name, []byte("sid"), 1000, 100)
	require.ErrorIs(t, err, sentinel)
	_, err = r.Renew(ctx, name, []byte("sid"), 1000, 100)
	require.ErrorIs(t, err, sentinel)
	_, err = r.Revoke(ctx, name, 1000, 100)
	require.ErrorIs(t, err, sentinel)
	_, err = r.Release(ctx, name, []byte("sid"))
	require.ErrorIs(t, err, sentinel)
	r.client = failingLeaseClient{deleteErr: sentinel}
	_, err = r.Release(ctx, name, []byte("sid"))
	require.ErrorIs(t, err, sentinel)
}

func TestLeaseRepositoryRejectsInvalidInputs(t *testing.T) {
	ctx := context.Background()
	name := leaseTestID(t)
	r := LeaseRepository{client: failingLeaseClient{}, tableName: TableName, validatorID: "test"}
	_, err := NewLeaseRepository(aws.Config{}, nil)
	require.Error(t, err)
	require.Error(t, r.RecordCall(ctx, name, nil, 1000, 100, 1))
	require.Error(t, r.RecordCall(ctx, name, []byte("sid"), 1000, 0, 1))
	_, err = r.Grant(ctx, name, nil, 1000, 100)
	require.Error(t, err)
	_, err = r.Grant(ctx, name, []byte("sid"), 1000, 0)
	require.Error(t, err)
	_, err = r.Renew(ctx, name, []byte("sid"), -1, 100)
	require.Error(t, err)
	_, err = r.Revoke(ctx, replica.ID{}, 1000, 100)
	require.Error(t, err)
	_, err = r.Release(ctx, name, nil)
	require.Error(t, err)
}
