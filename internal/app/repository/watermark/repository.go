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

// Package watermark stores durable watermark, lease, and session state in a
// single-region DynamoDB table. MREC global tables are not safe because their
// conditional writes evaluate region-local state and resolve conflicts later.
package watermark

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	smithyHTTP "github.com/aws/smithy-go/transport/http"
	"github.com/circlefin/arc-remote-signer/internal/common/replica"
	commonWatermark "github.com/circlefin/arc-remote-signer/internal/common/watermark"
)

var _ commonWatermark.OwnedAdvancer = (*Repository)(nil)

const (
	// TableName is the fixed DynamoDB table name for watermark, lease, and session items.
	TableName = "watermarks"
	// AggregateNamespace is the DynamoDB namespace key for aggregate state.
	AggregateNamespace = "state"

	validatorIDAttribute        = "validator_id"
	namespaceAttribute          = "namespace"
	versionAttribute            = "version"
	watermarksAttribute         = "watermarks"
	heightAttribute             = "height"
	roundAttribute              = "round"
	rankAttribute               = "rank"
	messageHashAttribute        = "message_hash"
	ownerHeightAttribute        = "owner_height"
	ownerReplicaNameAttribute   = "owner_replica_name"
	maxConditionalWriteAttempts = 8

	updateExpression = "SET #version = :next_version, #watermarks = :watermarks, " +
		"#owner_height = :owner_height, #owner_replica_name = :owner_replica_name"
	initialConditionExpression = "attribute_not_exists(#validator_id)"
	versionConditionExpression = "#version = :expected_version"
)

var legacyNamespaces = [...]commonWatermark.Namespace{
	commonWatermark.NamespacePrevotes,
	commonWatermark.NamespacePrecommits,
	commonWatermark.NamespaceProposals,
	commonWatermark.NamespaceProposalParts,
}

type itemClient interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

type storedState struct {
	version   uint64
	state     commonWatermark.State
	ownership commonWatermark.Ownership
}

// Repository stores one validator's aggregate watermark state in DynamoDB.
type Repository struct {
	client      itemClient
	tableName   string
	validatorID string

	mu          sync.Mutex
	initialized bool
	current     storedState
}

// New creates a DynamoDB watermark repository for one validator public key.
func New(cfg aws.Config, publicKey []byte) (*Repository, error) {
	repository, err := newRepository(dynamodb.NewFromConfig(cfg), TableName, publicKey)
	if err != nil {
		return nil, err
	}
	if err := repository.initialize(context.Background()); err != nil {
		return nil, fmt.Errorf("initialize DynamoDB watermark repository: %w", err)
	}
	return repository, nil
}

func newRepository(client itemClient, tableName string, publicKey []byte) (*Repository, error) {
	if client == nil {
		return nil, errors.New("DynamoDB client is required")
	}
	if strings.TrimSpace(tableName) == "" {
		return nil, errors.New("DynamoDB table name is required")
	}
	if len(publicKey) == 0 {
		return nil, errors.New("validator public key is required")
	}

	return &Repository{
		client:      client,
		tableName:   tableName,
		validatorID: hex.EncodeToString(publicKey),
	}, nil
}

// CompareAndAdvance applies the full host rule table and version-fences every
// accepted result. It refreshes cached state before watermark and ownership refusals.
func (r *Repository) CompareAndAdvance(
	ctx context.Context,
	namespace commonWatermark.Namespace,
	candidate commonWatermark.Watermark,
	owner replica.ID,
) (commonWatermark.Outcome, error) {
	if err := candidate.Validate(namespace); err != nil {
		return 0, err
	}
	if owner == (replica.ID{}) {
		return 0, fmt.Errorf("%w: replica identity is required", commonWatermark.ErrInvalidCandidate)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.initializeLocked(ctx); err != nil {
		return 0, err
	}

	for range maxConditionalWriteAttempts {
		next, nextOwnership, outcome, err := commonWatermark.AdvanceOwnedState(
			r.current.state,
			r.current.ownership,
			namespace,
			candidate,
			owner,
		)
		if err != nil {
			if err := r.refreshLocked(ctx); err != nil {
				return 0, err
			}
			next, nextOwnership, outcome, err = commonWatermark.AdvanceOwnedState(
				r.current.state,
				r.current.ownership,
				namespace,
				candidate,
				owner,
			)
			if err != nil {
				return 0, err
			}
		}
		if r.current.version == ^uint64(0) {
			return 0, fmt.Errorf("%w: DynamoDB watermark version is exhausted", commonWatermark.ErrWatermarkCorrupt)
		}
		_, err = r.client.UpdateItem(
			ctx,
			r.updateInput(r.current.version, next, nextOwnership),
		)
		if err == nil {
			r.current = storedState{
				version:   r.current.version + 1,
				state:     next,
				ownership: nextOwnership,
			}
			return outcome, nil
		}

		var conditionalFailure *dynamodbTypes.ConditionalCheckFailedException
		if !errors.As(err, &conditionalFailure) {
			return 0, classifyWriteError(err)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, ctxErr
		}
		current, decodeErr := decodeConditionalFailureState(conditionalFailure.Item)
		if decodeErr != nil {
			return 0, decodeErr
		}
		if current.version < r.current.version {
			return 0, fmt.Errorf("%w: DynamoDB watermark version regressed", commonWatermark.ErrWatermarkCorrupt)
		}
		r.current = current
	}

	return 0, fmt.Errorf(
		"DynamoDB watermark version race did not converge after %d attempts",
		maxConditionalWriteAttempts,
	)
}

func (r *Repository) initialize(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.initializeLocked(ctx)
}

func (r *Repository) initializeLocked(ctx context.Context) error {
	if r.initialized {
		return nil
	}
	if err := r.refreshLocked(ctx); err != nil {
		return err
	}
	r.initialized = true
	return nil
}

func (r *Repository) refreshLocked(ctx context.Context) error {
	current, err := r.readState(ctx)
	if err != nil {
		return err
	}
	if current.version < r.current.version {
		return fmt.Errorf("%w: DynamoDB watermark version regressed", commonWatermark.ErrWatermarkCorrupt)
	}
	r.current = current
	return nil
}

func decodeConditionalFailureState(item map[string]dynamodbTypes.AttributeValue) (storedState, error) {
	if len(item) == 0 {
		return storedState{}, errors.New("DynamoDB conditional failure returned no current watermark state")
	}
	current, err := decodeStoredState(item)
	if err != nil {
		return storedState{}, fmt.Errorf(
			"%w: decode DynamoDB conditional failure state: %v",
			commonWatermark.ErrWatermarkCorrupt,
			err,
		)
	}
	return current, nil
}

func (r *Repository) readState(ctx context.Context) (storedState, error) {
	output, err := r.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(r.tableName),
		Key:            r.key(AggregateNamespace),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return storedState{}, fmt.Errorf("get DynamoDB watermark state: %w", err)
	}
	if output == nil {
		return storedState{}, errors.New("DynamoDB returned no watermark read response")
	}
	if len(output.Item) != 0 {
		state, err := decodeStoredState(output.Item)
		if err != nil {
			return storedState{}, fmt.Errorf(
				"%w: decode DynamoDB watermark state: %v",
				commonWatermark.ErrWatermarkCorrupt,
				err,
			)
		}
		return state, nil
	}
	return r.readLegacyState(ctx)
}

func (r *Repository) readLegacyState(ctx context.Context) (storedState, error) {
	state := make(commonWatermark.State)
	ownersAtHeight := make(map[uint64]string)
	var highest uint64

	for _, namespace := range legacyNamespaces {
		output, err := r.client.GetItem(ctx, &dynamodb.GetItemInput{
			TableName:      aws.String(r.tableName),
			Key:            r.key(string(namespace)),
			ConsistentRead: aws.Bool(true),
		})
		if err != nil {
			return storedState{}, fmt.Errorf("get legacy DynamoDB %s watermark: %w", namespace, err)
		}
		if output == nil {
			return storedState{}, fmt.Errorf("DynamoDB returned no legacy %s watermark response", namespace)
		}
		if len(output.Item) == 0 {
			continue
		}

		stored, err := decodeWatermark(namespace, output.Item)
		if err != nil {
			return storedState{}, fmt.Errorf(
				"%w: decode legacy DynamoDB %s watermark: %v",
				commonWatermark.ErrWatermarkCorrupt,
				namespace,
				err,
			)
		}
		owner, err := decodeOwnerReplica(output.Item)
		if err != nil {
			return storedState{}, fmt.Errorf(
				"%w: decode legacy DynamoDB %s owner: %v",
				commonWatermark.ErrWatermarkCorrupt,
				namespace,
				err,
			)
		}
		state[namespace] = stored
		ownersAtHeight[stored.Tuple.Height] = mergeOwner(ownersAtHeight[stored.Tuple.Height], owner)
		if stored.Tuple.Height > highest {
			highest = stored.Tuple.Height
		}
	}

	if len(state) == 0 {
		return storedState{state: state}, nil
	}
	owner := ownersAtHeight[highest]
	if owner == "" || owner == conflictingOwner {
		return storedState{}, fmt.Errorf(
			"%w: legacy watermark owner at highest height %d is missing or conflicting",
			commonWatermark.ErrWatermarkCorrupt,
			highest,
		)
	}
	return storedState{
		state: state,
		ownership: commonWatermark.Ownership{
			Height:      highest,
			ReplicaName: owner,
		},
	}, nil
}

const conflictingOwner = "\x00"

func mergeOwner(current, next string) string {
	if current == conflictingOwner || next == "" {
		return conflictingOwner
	}
	if current == "" || current == next {
		return next
	}
	return conflictingOwner
}

func (r *Repository) updateInput(
	expectedVersion uint64,
	state commonWatermark.State,
	ownership commonWatermark.Ownership,
) *dynamodb.UpdateItemInput {
	names := map[string]string{
		"#version":            versionAttribute,
		"#watermarks":         watermarksAttribute,
		"#owner_height":       ownerHeightAttribute,
		"#owner_replica_name": ownerReplicaNameAttribute,
	}
	values := map[string]dynamodbTypes.AttributeValue{
		":next_version":       numberAttribute(expectedVersion + 1),
		":watermarks":         encodeState(state),
		":owner_height":       numberAttribute(ownership.Height),
		":owner_replica_name": &dynamodbTypes.AttributeValueMemberS{Value: ownership.ReplicaName},
	}
	condition := initialConditionExpression
	if expectedVersion == 0 {
		names["#validator_id"] = validatorIDAttribute
	} else {
		condition = versionConditionExpression
		values[":expected_version"] = numberAttribute(expectedVersion)
	}

	return &dynamodb.UpdateItemInput{
		TableName:                           aws.String(r.tableName),
		Key:                                 r.key(AggregateNamespace),
		ExpressionAttributeNames:            names,
		ExpressionAttributeValues:           values,
		UpdateExpression:                    aws.String(updateExpression),
		ConditionExpression:                 aws.String(condition),
		ReturnValuesOnConditionCheckFailure: dynamodbTypes.ReturnValuesOnConditionCheckFailureAllOld,
	}
}

func (r *Repository) key(namespace string) map[string]dynamodbTypes.AttributeValue {
	return map[string]dynamodbTypes.AttributeValue{
		validatorIDAttribute: &dynamodbTypes.AttributeValueMemberS{Value: r.validatorID},
		namespaceAttribute:   &dynamodbTypes.AttributeValueMemberS{Value: namespace},
	}
}

func classifyWriteError(err error) error {
	var responseError *smithyHTTP.ResponseError
	if errors.As(err, &responseError) &&
		responseError.HTTPStatusCode() >= http.StatusBadRequest &&
		responseError.HTTPStatusCode() < http.StatusInternalServerError {
		return fmt.Errorf("update DynamoDB watermark: %w", err)
	}
	return fmt.Errorf(
		"%w: update DynamoDB watermark: %w",
		commonWatermark.ErrWatermarkIndeterminate,
		err,
	)
}

func encodeState(state commonWatermark.State) dynamodbTypes.AttributeValue {
	watermarks := make(map[string]dynamodbTypes.AttributeValue, len(state))
	for namespace, stored := range state {
		watermarks[string(namespace)] = &dynamodbTypes.AttributeValueMemberM{Value: map[string]dynamodbTypes.AttributeValue{
			heightAttribute:      numberAttribute(stored.Tuple.Height),
			roundAttribute:       numberAttribute(stored.Tuple.Round),
			rankAttribute:        numberAttribute(uint64(stored.Tuple.Rank)),
			messageHashAttribute: &dynamodbTypes.AttributeValueMemberB{Value: stored.MessageHash[:]},
		}}
	}
	return &dynamodbTypes.AttributeValueMemberM{Value: watermarks}
}

func decodeStoredState(item map[string]dynamodbTypes.AttributeValue) (storedState, error) {
	version, err := decodeNumber(item, versionAttribute)
	if err != nil {
		return storedState{}, err
	}
	if version == 0 {
		return storedState{}, errors.New("DynamoDB watermark version must be greater than zero")
	}
	watermarks, ok := item[watermarksAttribute].(*dynamodbTypes.AttributeValueMemberM)
	if !ok {
		return storedState{}, errors.New("DynamoDB watermarks must be a map")
	}
	state := make(commonWatermark.State, len(watermarks.Value))
	for rawNamespace, value := range watermarks.Value {
		namespace := commonWatermark.Namespace(rawNamespace)
		encoded, ok := value.(*dynamodbTypes.AttributeValueMemberM)
		if !ok {
			return storedState{}, fmt.Errorf("DynamoDB %s watermark must be a map", namespace)
		}
		stored, err := decodeWatermark(namespace, encoded.Value)
		if err != nil {
			return storedState{}, fmt.Errorf("decode %s watermark: %w", namespace, err)
		}
		state[namespace] = stored
	}
	if len(state) == 0 {
		if _, hasHeight := item[ownerHeightAttribute]; hasHeight {
			return storedState{}, errors.New("empty DynamoDB watermark state must not have an owner height")
		}
		if _, hasOwner := item[ownerReplicaNameAttribute]; hasOwner {
			return storedState{}, errors.New("empty DynamoDB watermark state must not have an owner replica")
		}
		return storedState{version: version, state: state}, nil
	}

	ownerHeight, err := decodeNumber(item, ownerHeightAttribute)
	if err != nil {
		return storedState{}, err
	}
	owner, err := decodeOwnerReplica(item)
	if err != nil {
		return storedState{}, err
	}
	if owner == "" {
		return storedState{}, errors.New("DynamoDB watermark owner_replica_name is required")
	}
	var highest uint64
	for _, watermark := range state {
		if watermark.Tuple.Height > highest {
			highest = watermark.Tuple.Height
		}
	}
	if ownerHeight != highest {
		return storedState{}, fmt.Errorf(
			"DynamoDB owner height %d does not match highest watermark height %d",
			ownerHeight,
			highest,
		)
	}
	return storedState{
		version: version,
		state:   state,
		ownership: commonWatermark.Ownership{
			Height:      ownerHeight,
			ReplicaName: owner,
		},
	}, nil
}

func numberAttribute(value uint64) dynamodbTypes.AttributeValue {
	return &dynamodbTypes.AttributeValueMemberN{Value: strconv.FormatUint(value, 10)}
}

func decodeWatermark(
	namespace commonWatermark.Namespace,
	item map[string]dynamodbTypes.AttributeValue,
) (commonWatermark.Watermark, error) {
	height, err := decodeNumber(item, heightAttribute)
	if err != nil {
		return commonWatermark.Watermark{}, err
	}
	round, err := decodeNumber(item, roundAttribute)
	if err != nil {
		return commonWatermark.Watermark{}, err
	}
	rank, err := decodeNumber(item, rankAttribute)
	if err != nil {
		return commonWatermark.Watermark{}, err
	}
	if rank > uint64(^commonWatermark.Rank(0)) {
		return commonWatermark.Watermark{}, fmt.Errorf("DynamoDB watermark rank %d exceeds its domain", rank)
	}

	hashAttribute, ok := item[messageHashAttribute].(*dynamodbTypes.AttributeValueMemberB)
	if !ok {
		return commonWatermark.Watermark{}, errors.New("DynamoDB watermark message_hash must be binary")
	}
	var messageHash commonWatermark.MessageHash
	if len(hashAttribute.Value) != len(messageHash) {
		return commonWatermark.Watermark{}, fmt.Errorf(
			"DynamoDB watermark message_hash must contain %d bytes",
			len(messageHash),
		)
	}
	copy(messageHash[:], hashAttribute.Value)

	stored := commonWatermark.Watermark{
		Tuple: commonWatermark.Tuple{
			Height: height,
			Round:  round,
			Rank:   commonWatermark.Rank(rank),
		},
		MessageHash: messageHash,
	}
	if err := stored.Validate(namespace); err != nil {
		return commonWatermark.Watermark{}, fmt.Errorf("invalid stored watermark: %w", err)
	}
	return stored, nil
}

func decodeOwnerReplica(item map[string]dynamodbTypes.AttributeValue) (string, error) {
	attribute, ok := item[ownerReplicaNameAttribute]
	if !ok {
		return "", nil
	}
	replicaAttr, ok := attribute.(*dynamodbTypes.AttributeValueMemberS)
	if !ok {
		return "", errors.New("DynamoDB watermark owner_replica_name must be a string")
	}
	if replicaAttr.Value == "" {
		return "", errors.New("DynamoDB watermark owner_replica_name must be non-empty")
	}
	if _, err := replica.NewID(replicaAttr.Value); err != nil {
		return "", fmt.Errorf("DynamoDB watermark owner_replica_name is invalid: %w", err)
	}
	return replicaAttr.Value, nil
}

func decodeNumber(item map[string]dynamodbTypes.AttributeValue, name string) (uint64, error) {
	attribute, ok := item[name].(*dynamodbTypes.AttributeValueMemberN)
	if !ok {
		return 0, fmt.Errorf("DynamoDB watermark %s must be a number", name)
	}
	value, err := strconv.ParseUint(attribute.Value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse DynamoDB watermark %s: %w", name, err)
	}
	return value, nil
}
