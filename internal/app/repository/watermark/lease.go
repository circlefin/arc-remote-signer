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
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/circlefin/arc-remote-signer/internal/common/replica"
)

// ErrDuplicateName means another process used this replica name within one TTL.
var ErrDuplicateName = errors.New("duplicate replica name")

// ErrContended means repeated concurrent session changes prevented a stable update.
var ErrContended = errors.New("session record changed during update")

type leaseClient interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
}

// Lease contains one validator's current holder and revocation state.
type Lease struct {
	Holder           string
	SessionID        []byte
	ExpiresAt        int64
	RevokedName      string
	RevocationEndsAt int64
}

// Session contains one node's most recently accepted call and progress.
type Session struct {
	SessionID       []byte
	LastCallAt      int64
	DecidedHeight   uint64
	HeightChangedAt int64
}

// LeaseRepository stores the lease and sessions for one validator.
type LeaseRepository struct {
	client      leaseClient
	validatorID string
	tableName   string
}

// NewLeaseRepository constructs a lease repository keyed by a validator public key.
func NewLeaseRepository(cfg aws.Config, publicKey []byte) (*LeaseRepository, error) {
	if len(publicKey) == 0 {
		return nil, errors.New("validator public key is required")
	}
	return &LeaseRepository{client: dynamodb.NewFromConfig(cfg), validatorID: hex.EncodeToString(publicKey), tableName: TableName}, nil
}

func (r *LeaseRepository) key(namespace string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"validator_id": &types.AttributeValueMemberS{Value: r.validatorID}, "namespace": &types.AttributeValueMemberS{Value: namespace}}
}
func sessionKey(name replica.ID) string { return "session#" + name.String() }
func s(v string) types.AttributeValue   { return &types.AttributeValueMemberS{Value: v} }
func n(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}
func b(v []byte) types.AttributeValue { return &types.AttributeValueMemberB{Value: v} }
func conditional(err error) bool {
	var failed *types.ConditionalCheckFailedException
	return errors.As(err, &failed)
}
func identity(name replica.ID, sid []byte) error {
	if name.String() == "" || len(sid) == 0 || len(sid) > 64 {
		return errors.New("valid replica name and 1..64 byte session ID are required")
	}
	return nil
}
func future(now, duration int64) (int64, error) {
	if now < 0 || duration <= 0 || duration > math.MaxInt64-now {
		return 0, errors.New("invalid timestamp or duration")
	}
	return now + duration, nil
}
func names(keys ...string) map[string]string {
	all := map[string]string{"holder": "holder", "sid": "session_id", "expires": "expires_at", "revoked": "revoked_name", "revocation_end": "revocation_ends_at", "last": "last_call_at", "height": "decided_height", "changed": "height_changed_at"}
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		result["#"+key] = all[key]
	}
	return result
}

// ReadLease reads the lease item consistently. The bool reports whether it exists.
func (r *LeaseRepository) ReadLease(ctx context.Context) (Lease, bool, error) {
	out, err := r.client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(r.tableName), Key: r.key("lease"), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return Lease{}, false, fmt.Errorf("read lease: %w", err)
	}
	if len(out.Item) == 0 {
		return Lease{}, false, nil
	}
	var l Lease
	if l.Holder, err = optionalString(out.Item, "holder"); err != nil {
		return Lease{}, false, err
	}
	if l.SessionID, err = optionalBytes(out.Item, "session_id"); err != nil {
		return Lease{}, false, err
	}
	if l.ExpiresAt, err = optionalNumber(out.Item, "expires_at"); err != nil {
		return Lease{}, false, err
	}
	if l.RevokedName, err = optionalString(out.Item, "revoked_name"); err != nil {
		return Lease{}, false, err
	}
	if l.RevocationEndsAt, err = optionalNumber(out.Item, "revocation_ends_at"); err != nil {
		return Lease{}, false, err
	}
	if l.Holder != "" && (len(l.SessionID) == 0 || l.ExpiresAt <= 0) {
		return Lease{}, false, errors.New("corrupt lease holder state")
	}
	if l.Holder == "" && (len(l.SessionID) != 0 || l.ExpiresAt != 0) {
		return Lease{}, false, errors.New("corrupt empty lease state")
	}
	if l.RevokedName != "" && l.RevocationEndsAt <= 0 {
		return Lease{}, false, errors.New("corrupt revocation state")
	}
	return l, true, nil
}

// ReadSession reads one replica's session item consistently.
func (r *LeaseRepository) ReadSession(ctx context.Context, name replica.ID) (Session, bool, error) {
	if name.String() == "" {
		return Session{}, false, errors.New("replica name is required")
	}
	out, err := r.client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(r.tableName), Key: r.key(sessionKey(name)), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return Session{}, false, fmt.Errorf("read session: %w", err)
	}
	if len(out.Item) == 0 {
		return Session{}, false, nil
	}
	var v Session
	if v.SessionID, err = requiredBytes(out.Item, "session_id"); err != nil {
		return Session{}, false, err
	}
	if v.LastCallAt, err = requiredNumber(out.Item, "last_call_at"); err != nil {
		return Session{}, false, err
	}
	h, e := requiredNumber(out.Item, "decided_height")
	if e != nil {
		return Session{}, false, e
	}
	if h < 0 {
		return Session{}, false, errors.New("negative decided height")
	}
	v.DecidedHeight = uint64(h)
	if v.HeightChangedAt, err = requiredNumber(out.Item, "height_changed_at"); err != nil {
		return Session{}, false, err
	}
	return v, true, nil
}

// RecordCall keeps one process per replica name for one TTL. It also records progress.
func (r *LeaseRepository) RecordCall(ctx context.Context, name replica.ID, sid []byte, now, ttl int64, height uint64) error {
	if err := identity(name, sid); err != nil {
		return err
	}
	if now < 0 || ttl <= 0 {
		return errors.New("invalid timestamp or TTL")
	}
	cutoff := now - ttl
	if cutoff > now {
		cutoff = math.MinInt64
	}
	if height > math.MaxInt64 {
		return errors.New("decided height exceeds DynamoDB number range")
	}
	for attempt := 0; attempt < 5; attempt++ {
		previous, exists, err := r.ReadSession(ctx, name)
		if err != nil {
			return err
		}
		if exists && string(previous.SessionID) != string(sid) && previous.LastCallAt >= cutoff {
			return ErrDuplicateName
		}
		if exists && string(previous.SessionID) == string(sid) {
			if previous.LastCallAt > now {
				return nil
			}
			if previous.DecidedHeight > height {
				height = previous.DecidedHeight
			}
		}
		changed := now
		if exists && previous.DecidedHeight == height && string(previous.SessionID) == string(sid) {
			changed = previous.HeightChangedAt
		}
		values := map[string]types.AttributeValue{":sid": b(sid), ":now": n(now), ":height": n(int64(height)), ":changed": n(changed)}
		condition := "attribute_not_exists(#sid)"
		if exists {
			condition = "(#sid = :sid OR #last < :cutoff) AND #last = :previous AND #last <= :now AND (#sid <> :sid OR #height <= :height)"
			values[":previous"] = n(previous.LastCallAt)
			values[":cutoff"] = n(cutoff)
		}
		_, err = r.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: aws.String(r.tableName), Key: r.key(sessionKey(name)), UpdateExpression: aws.String("SET #sid = :sid, #last = :now, #height = :height, #changed = :changed"), ConditionExpression: aws.String(condition), ExpressionAttributeNames: names("sid", "last", "height", "changed"), ExpressionAttributeValues: values})
		if err == nil {
			return nil
		}
		if !conditional(err) {
			return fmt.Errorf("record session call: %w", err)
		}
	}
	return ErrContended
}

// Grant claims a free lease unless this replica is still revoked.
func (r *LeaseRepository) Grant(ctx context.Context, name replica.ID, sid []byte, now, ttl int64) (bool, error) {
	if err := identity(name, sid); err != nil {
		return false, err
	}
	until, err := future(now, ttl)
	if err != nil {
		return false, err
	}
	_, err = r.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: aws.String(r.tableName), Key: r.key("lease"), UpdateExpression: aws.String("SET #holder = :name, #sid = :sid, #expires = :until"), ConditionExpression: aws.String("(attribute_not_exists(#holder) OR #expires < :now) AND (attribute_not_exists(#revoked) OR #revoked <> :name OR #revocation_end < :now)"), ExpressionAttributeNames: names("holder", "sid", "expires", "revoked", "revocation_end"), ExpressionAttributeValues: map[string]types.AttributeValue{":name": s(name.String()), ":sid": b(sid), ":until": n(until), ":now": n(now)}})
	if conditional(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("grant lease: %w", err)
	}
	return true, nil
}

// Renew extends only the unexpired lease of this exact process.
// It refuses a renewal that would shorten the stored expiry.
// The bool reports whether the expiry write was accepted. A false result does
// not prove lease loss: a newer renewal may already have stored a later expiry.
// Callers must read the current lease to distinguish these cases before making
// a role decision. The read does not replace the lease check on each signature.
func (r *LeaseRepository) Renew(ctx context.Context, name replica.ID, sid []byte, now, ttl int64) (bool, error) {
	if err := identity(name, sid); err != nil {
		return false, err
	}
	until, err := future(now, ttl)
	if err != nil {
		return false, err
	}
	_, err = r.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: aws.String(r.tableName), Key: r.key("lease"), UpdateExpression: aws.String("SET #expires = :until"), ConditionExpression: aws.String("#holder = :name AND #sid = :sid AND #expires >= :now AND #expires <= :until"), ExpressionAttributeNames: names("holder", "sid", "expires"), ExpressionAttributeValues: map[string]types.AttributeValue{":name": s(name.String()), ":sid": b(sid), ":until": n(until), ":now": n(now)}})
	if conditional(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("renew lease: %w", err)
	}
	return true, nil
}

// Release frees a matching lease, then removes that process's session item.
func (r *LeaseRepository) Release(ctx context.Context, name replica.ID, sid []byte) (bool, error) {
	if err := identity(name, sid); err != nil {
		return false, err
	}
	values := map[string]types.AttributeValue{":name": s(name.String()), ":sid": b(sid)}
	_, err := r.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: aws.String(r.tableName), Key: r.key("lease"), UpdateExpression: aws.String("REMOVE #holder, #sid, #expires"), ConditionExpression: aws.String("#holder = :name AND #sid = :sid"), ExpressionAttributeNames: names("holder", "sid", "expires"), ExpressionAttributeValues: values})
	released := err == nil
	if err != nil && !conditional(err) {
		return false, fmt.Errorf("release lease: %w", err)
	}
	_, err = r.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(r.tableName), Key: r.key(sessionKey(name)), ConditionExpression: aws.String("#sid = :sid"), ExpressionAttributeNames: names("sid"), ExpressionAttributeValues: map[string]types.AttributeValue{":sid": b(sid)}})
	if conditional(err) {
		return released, nil
	}
	if err != nil {
		return released, fmt.Errorf("delete released session: %w", err)
	}
	return released, nil
}

// Revoke clears a named holder and bars that name until the revocation ends.
func (r *LeaseRepository) Revoke(ctx context.Context, name replica.ID, now, duration int64) (bool, error) {
	if name.String() == "" {
		return false, errors.New("replica name is required")
	}
	until, err := future(now, duration)
	if err != nil {
		return false, err
	}
	_, err = r.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: aws.String(r.tableName), Key: r.key("lease"), UpdateExpression: aws.String("SET #revoked = :name, #revocation_end = :until REMOVE #holder, #sid, #expires"), ConditionExpression: aws.String("#holder = :name"), ExpressionAttributeNames: names("holder", "sid", "expires", "revoked", "revocation_end"), ExpressionAttributeValues: map[string]types.AttributeValue{":name": s(name.String()), ":until": n(until)}})
	if conditional(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("revoke lease: %w", err)
	}
	return true, nil
}

func optionalString(item map[string]types.AttributeValue, key string) (string, error) {
	v, ok := item[key]
	if !ok {
		return "", nil
	}
	x, ok := v.(*types.AttributeValueMemberS)
	if !ok {
		return "", fmt.Errorf("invalid %s attribute", key)
	}
	return x.Value, nil
}
func optionalBytes(item map[string]types.AttributeValue, key string) ([]byte, error) {
	v, ok := item[key]
	if !ok {
		return nil, nil
	}
	x, ok := v.(*types.AttributeValueMemberB)
	if !ok {
		return nil, fmt.Errorf("invalid %s attribute", key)
	}
	return x.Value, nil
}
func optionalNumber(item map[string]types.AttributeValue, key string) (int64, error) {
	v, ok := item[key]
	if !ok {
		return 0, nil
	}
	x, ok := v.(*types.AttributeValueMemberN)
	if !ok {
		return 0, fmt.Errorf("invalid %s attribute", key)
	}
	n, err := strconv.ParseInt(x.Value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s attribute: %w", key, err)
	}
	return n, nil
}
func requiredBytes(item map[string]types.AttributeValue, key string) ([]byte, error) {
	v, err := optionalBytes(item, key)
	if err != nil {
		return nil, err
	}
	if len(v) == 0 {
		return nil, fmt.Errorf("missing %s attribute", key)
	}
	return v, nil
}
func requiredNumber(item map[string]types.AttributeValue, key string) (int64, error) {
	if _, ok := item[key]; !ok {
		return 0, fmt.Errorf("missing %s attribute", key)
	}
	return optionalNumber(item, key)
}
