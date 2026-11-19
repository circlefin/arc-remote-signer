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

//go:build integration

package watermark

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/circlefin/arc-remote-signer/internal/common/replica"
	"github.com/stretchr/testify/require"
)

func newTestLeaseRepository(t *testing.T) *LeaseRepository {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion("us-east-1"), awsconfig.WithBaseEndpoint("http://localhost:4566"), awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	require.NoError(t, err)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	repo, err := NewLeaseRepository(cfg, key)
	require.NoError(t, err)
	t.Cleanup(func() {
		client := dynamodb.NewFromConfig(cfg)
		for _, key := range []string{"lease", "session#a", "session#b"} {
			if _, err := client.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{TableName: aws.String(TableName), Key: repo.key(key)}); err != nil {
				t.Errorf("clean up %s: %v", key, err)
			}
		}
	})
	return repo
}
func leaseTestReplica(t *testing.T, name string) replica.ID {
	t.Helper()
	v, err := replica.NewID(name)
	require.NoError(t, err)
	return v
}

func TestIntegrationLeaseContentionAndRevocation(t *testing.T) {
	r := newTestLeaseRepository(t)
	ctx := context.Background()
	a := leaseTestReplica(t, "a")
	b := leaseTestReplica(t, "b")
	now := int64(10000)
	ttl := int64(1000)
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for _, name := range []replica.ID{a, b} {
		wg.Add(1)
		go func(name replica.ID) {
			defer wg.Done()
			ok, err := r.Grant(ctx, name, []byte(name.String()), now, ttl)
			if err != nil {
				t.Errorf("grant: %v", err)
			}
			results <- ok
		}(name)
	}
	wg.Wait()
	close(results)
	count := 0
	for ok := range results {
		if ok {
			count++
		}
	}
	require.Equal(t, 1, count)
	lease, exists, err := r.ReadLease(ctx)
	require.NoError(t, err)
	require.True(t, exists)
	holder := leaseTestReplica(t, lease.Holder)
	ok, err := r.Renew(ctx, holder, []byte("wrong"), now+1, ttl)
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = r.Revoke(ctx, holder, now+2, 500)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = r.Renew(ctx, holder, lease.SessionID, now+3, ttl)
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = r.Grant(ctx, holder, lease.SessionID, now+3, ttl)
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = r.Grant(ctx, holder, lease.SessionID, now+503, ttl)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestIntegrationLeaseRenewalPreservesLaterExpiry(t *testing.T) {
	r := newTestLeaseRepository(t)
	ctx := context.Background()
	a, backup := leaseTestReplica(t, "a"), leaseTestReplica(t, "b")
	sid := []byte("holder")
	ok, err := r.Grant(ctx, a, sid, 10000, 1000)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = r.Renew(ctx, a, sid, 10200, 1000)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = r.Renew(ctx, a, sid, 10100, 1000)
	require.NoError(t, err)
	require.False(t, ok)
	lease, exists, err := r.ReadLease(ctx)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, int64(11200), lease.ExpiresAt)
	ok, err = r.Grant(ctx, backup, []byte("backup"), 11101, 1000)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestIntegrationSessionDuplicateAndProgress(t *testing.T) {
	r := newTestLeaseRepository(t)
	ctx := context.Background()
	a := leaseTestReplica(t, "a")
	now := int64(10000)
	ttl := int64(1000)
	require.NoError(t, r.RecordCall(ctx, a, []byte("first"), now, ttl, 10))
	err := r.RecordCall(ctx, a, []byte("second"), now+1, ttl, 11)
	require.ErrorIs(t, err, ErrDuplicateName)
	v, exists, err := r.ReadSession(ctx, a)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, int64(10000), v.HeightChangedAt)
	require.Equal(t, uint64(10), v.DecidedHeight)
	require.NoError(t, r.RecordCall(ctx, a, []byte("first"), now+2, ttl, 10))
	v, _, err = r.ReadSession(ctx, a)
	require.NoError(t, err)
	require.Equal(t, int64(10000), v.HeightChangedAt)
	require.NoError(t, r.RecordCall(ctx, a, []byte("first"), now+3, ttl, 11))
	v, _, err = r.ReadSession(ctx, a)
	require.NoError(t, err)
	require.Equal(t, int64(10003), v.HeightChangedAt)
	require.NoError(t, r.RecordCall(ctx, a, []byte("first"), now+2, ttl, 10))
	require.NoError(t, r.RecordCall(ctx, a, []byte("first"), now+3, ttl, 10))
	v, _, err = r.ReadSession(ctx, a)
	require.NoError(t, err)
	require.Equal(t, int64(10003), v.LastCallAt)
	require.Equal(t, uint64(11), v.DecidedHeight)
	require.NoError(t, r.RecordCall(ctx, a, []byte("first"), now+4, ttl, 10))
	v, _, err = r.ReadSession(ctx, a)
	require.NoError(t, err)
	require.Equal(t, int64(10004), v.LastCallAt)
	require.Equal(t, uint64(11), v.DecidedHeight)
	require.Equal(t, int64(10003), v.HeightChangedAt)
	err = r.RecordCall(ctx, a, []byte("second"), now+1003, ttl, 12)
	require.ErrorIs(t, err, ErrDuplicateName)
	require.NoError(t, r.RecordCall(ctx, a, []byte("second"), now+1005, ttl, 12))
}

func TestIntegrationReleaseMatchesProcess(t *testing.T) {
	r := newTestLeaseRepository(t)
	ctx := context.Background()
	a := leaseTestReplica(t, "a")
	now := int64(10000)
	ttl := int64(1000)
	require.NoError(t, r.RecordCall(ctx, a, []byte("old"), now, ttl, 1))
	ok, err := r.Grant(ctx, a, []byte("old"), now, ttl)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, r.RecordCall(ctx, a, []byte("new"), now+1001, ttl, 2))
	ok, err = r.Grant(ctx, a, []byte("new"), now+1001, ttl)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = r.Release(ctx, a, []byte("old"))
	require.NoError(t, err)
	require.False(t, ok)
	lease, _, err := r.ReadLease(ctx)
	require.NoError(t, err)
	require.Equal(t, "new", string(lease.SessionID))
	session, _, err := r.ReadSession(ctx, a)
	require.NoError(t, err)
	require.Equal(t, "new", string(session.SessionID))
	ok, err = r.Release(ctx, a, []byte("new"))
	require.NoError(t, err)
	require.True(t, ok)
	_, exists, err := r.ReadSession(ctx, a)
	require.NoError(t, err)
	require.False(t, exists)
	lease, _, err = r.ReadLease(ctx)
	require.NoError(t, err)
	require.Empty(t, lease.Holder)
	ok, err = r.Release(ctx, a, []byte("new"))
	require.NoError(t, err)
	require.False(t, ok)
}

func TestIntegrationReleaseRetryCleansSession(t *testing.T) {
	r := newTestLeaseRepository(t)
	ctx := context.Background()
	a := leaseTestReplica(t, "a")
	sid := []byte("same")
	require.NoError(t, r.RecordCall(ctx, a, sid, 10000, 1000, 1))
	ok, err := r.Grant(ctx, a, sid, 10000, 1000)
	require.NoError(t, err)
	require.True(t, ok)
	_, err = r.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: aws.String(TableName), Key: r.key("lease"), UpdateExpression: aws.String("REMOVE #holder, #sid, #expires"), ExpressionAttributeNames: names("holder", "sid", "expires")})
	require.NoError(t, err)
	ok, err = r.Release(ctx, a, sid)
	require.NoError(t, err)
	require.False(t, ok)
	_, exists, err := r.ReadSession(ctx, a)
	require.NoError(t, err)
	require.False(t, exists)
}

func TestIntegrationBackupReleaseCleansSession(t *testing.T) {
	r := newTestLeaseRepository(t)
	ctx := context.Background()
	a, backup := leaseTestReplica(t, "a"), leaseTestReplica(t, "b")
	require.NoError(t, r.RecordCall(ctx, a, []byte("primary"), 10000, 1000, 1))
	require.NoError(t, r.RecordCall(ctx, backup, []byte("backup"), 10000, 1000, 1))
	ok, err := r.Grant(ctx, a, []byte("primary"), 10000, 1000)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = r.Release(ctx, backup, []byte("backup"))
	require.NoError(t, err)
	require.False(t, ok)
	lease, _, err := r.ReadLease(ctx)
	require.NoError(t, err)
	require.Equal(t, "a", lease.Holder)
	require.Equal(t, []byte("primary"), lease.SessionID)
	require.NoError(t, r.RecordCall(ctx, backup, []byte("restarted"), 10001, 1000, 1))
}
