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
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
	smithyHTTP "github.com/aws/smithy-go/transport/http"
	"github.com/circlefin/arc-remote-signer/internal/common/replica"
	commonWatermark "github.com/circlefin/arc-remote-signer/internal/common/watermark"
	"github.com/stretchr/testify/require"
)

type fakeDynamoDBClient struct {
	getItem    func(context.Context, *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
	updateItem func(context.Context, *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error)
}

func (f *fakeDynamoDBClient) GetItem(
	ctx context.Context,
	input *dynamodb.GetItemInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.GetItemOutput, error) {
	if f.getItem == nil {
		return &dynamodb.GetItemOutput{}, nil
	}
	return f.getItem(ctx, input)
}

func (f *fakeDynamoDBClient) UpdateItem(
	ctx context.Context,
	input *dynamodb.UpdateItemInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.UpdateItemOutput, error) {
	if f.updateItem == nil {
		return &dynamodb.UpdateItemOutput{}, nil
	}
	return f.updateItem(ctx, input)
}

func mustReplicaID(t *testing.T, name string) replica.ID {
	t.Helper()
	id, err := replica.NewID(name)
	require.NoError(t, err)
	return id
}

func TestRepository_ReadsAggregateStateBeforeVersionedWrite(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	current := testWatermark(10, 1, commonWatermark.RankFirst, "prevote-10")
	candidate := testWatermark(10, 2, commonWatermark.RankFirst, "prevote-10-2")
	reads := 0
	var write *dynamodb.UpdateItemInput
	client := &fakeDynamoDBClient{
		getItem: func(_ context.Context, input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			reads++
			require.True(t, aws.ToBool(input.ConsistentRead))
			require.Equal(t, AggregateNamespace, attributeString(t, input.Key[namespaceAttribute]))
			return &dynamodb.GetItemOutput{Item: testAggregateItem(
				"0102", 7,
				commonWatermark.State{commonWatermark.NamespacePrevotes: current},
				commonWatermark.Ownership{Height: 10, ReplicaName: replicaA.String()},
			)}, nil
		},
		updateItem: func(_ context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			write = input
			return &dynamodb.UpdateItemOutput{}, nil
		},
	}
	repository, err := newRepository(client, "watermarks", []byte{0x01, 0x02})
	require.NoError(t, err)

	outcome, err := repository.CompareAndAdvance(
		context.Background(), commonWatermark.NamespacePrevotes, candidate, replicaA,
	)

	require.NoError(t, err)
	require.Equal(t, commonWatermark.OutcomeAdvanced, outcome)
	require.Equal(t, 1, reads)
	require.Equal(t, AggregateNamespace, attributeString(t, write.Key[namespaceAttribute]))
	require.Equal(t, "7", attributeNumber(t, write.ExpressionAttributeValues[":expected_version"]))
	require.Equal(t, "8", attributeNumber(t, write.ExpressionAttributeValues[":next_version"]))
	require.Equal(t, versionConditionExpression, aws.ToString(write.ConditionExpression))
	require.NotContains(t, write.ExpressionAttributeNames, "#validator_id")
	require.Equal(
		t,
		dynamodbTypes.ReturnValuesOnConditionCheckFailureAllOld,
		write.ReturnValuesOnConditionCheckFailure,
	)

	outcome, err = repository.CompareAndAdvance(
		context.Background(),
		commonWatermark.NamespacePrevotes,
		testWatermark(10, 3, commonWatermark.RankFirst, "prevote-10-3"),
		replicaA,
	)
	require.NoError(t, err)
	require.Equal(t, commonWatermark.OutcomeAdvanced, outcome)
	require.Equal(t, 1, reads, "successful writes must advance the in-memory copy")
}

func TestRepository_RetriesConditionalRaceFromReturnedItem(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	reads, writes := 0, 0
	client := &fakeDynamoDBClient{
		getItem: func(context.Context, *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			reads++
			return &dynamodb.GetItemOutput{Item: testAggregateItem(
				"01", 1, commonWatermark.State{}, commonWatermark.Ownership{},
			)}, nil
		},
		updateItem: func(_ context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			writes++
			if writes == 1 {
				require.Equal(t, "1", attributeNumber(t, input.ExpressionAttributeValues[":expected_version"]))
				return nil, &dynamodbTypes.ConditionalCheckFailedException{Item: testAggregateItem(
					"01", 2, commonWatermark.State{}, commonWatermark.Ownership{},
				)}
			}
			require.Equal(t, "2", attributeNumber(t, input.ExpressionAttributeValues[":expected_version"]))
			return &dynamodb.UpdateItemOutput{}, nil
		},
	}
	repository, err := newRepository(client, "watermarks", []byte{0x01})
	require.NoError(t, err)

	_, err = repository.CompareAndAdvance(
		context.Background(), commonWatermark.NamespacePrevotes,
		testWatermark(10, 2, commonWatermark.RankFirst, "candidate"), replicaA,
	)

	require.NoError(t, err)
	require.Equal(t, 1, reads)
	require.Equal(t, 2, writes)
}

func TestRepository_StopsAfterConditionalWriteAttemptLimit(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	reads, writes := 0, 0
	client := &fakeDynamoDBClient{
		getItem: func(context.Context, *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			reads++
			return &dynamodb.GetItemOutput{Item: testAggregateItem(
				"01", 1, commonWatermark.State{}, commonWatermark.Ownership{},
			)}, nil
		},
		updateItem: func(context.Context, *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			writes++
			return nil, &dynamodbTypes.ConditionalCheckFailedException{Item: testAggregateItem(
				"01", uint64(writes+1), commonWatermark.State{}, commonWatermark.Ownership{},
			)}
		},
	}
	repository, err := newRepository(client, "watermarks", []byte{0x01})
	require.NoError(t, err)

	_, err = repository.CompareAndAdvance(
		context.Background(), commonWatermark.NamespacePrevotes,
		testWatermark(10, 2, commonWatermark.RankFirst, "candidate"), replicaA,
	)

	require.Error(t, err)
	require.NotErrorIs(t, err, commonWatermark.ErrWatermarkIndeterminate)
	require.ErrorContains(t, err, "did not converge after 8 attempts")
	require.Equal(t, 1, reads)
	require.Equal(t, 8, writes)
}

func TestRepository_StopsConditionalWriteRetriesWhenContextEnds(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	ctx, cancel := context.WithCancel(context.Background())
	writes := 0
	client := &fakeDynamoDBClient{
		updateItem: func(context.Context, *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			writes++
			cancel()
			return nil, &dynamodbTypes.ConditionalCheckFailedException{}
		},
	}
	repository, err := newRepository(client, "watermarks", []byte{0x01})
	require.NoError(t, err)

	_, err = repository.CompareAndAdvance(
		ctx, commonWatermark.NamespacePrevotes,
		testWatermark(10, 2, commonWatermark.RankFirst, "candidate"), replicaA,
	)

	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, writes)
}

func TestRepository_FoldsLegacyNamespacesIntoFirstAggregateWrite(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	replicaB := mustReplicaID(t, "replica-b")
	prevote := testWatermark(10, 1, commonWatermark.RankFirst, "prevote")
	precommit := testWatermark(10, 2, commonWatermark.RankFirst, "precommit")
	candidate := testWatermark(11, 0, commonWatermark.RankFirst, "proposal")
	var write *dynamodb.UpdateItemInput
	client := &fakeDynamoDBClient{
		getItem: func(_ context.Context, input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			namespace := attributeString(t, input.Key[namespaceAttribute])
			switch namespace {
			case AggregateNamespace, string(commonWatermark.NamespaceProposals), string(commonWatermark.NamespaceProposalParts):
				return &dynamodb.GetItemOutput{}, nil
			case string(commonWatermark.NamespacePrevotes):
				return &dynamodb.GetItemOutput{Item: testOwnedItem("01", commonWatermark.NamespacePrevotes, prevote, replicaA.String())}, nil
			case string(commonWatermark.NamespacePrecommits):
				return &dynamodb.GetItemOutput{Item: testOwnedItem("01", commonWatermark.NamespacePrecommits, precommit, replicaA.String())}, nil
			default:
				t.Fatalf("unexpected namespace read %q", namespace)
				return nil, nil
			}
		},
		updateItem: func(_ context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			write = input
			return &dynamodb.UpdateItemOutput{}, nil
		},
	}
	repository, err := newRepository(client, "watermarks", []byte{0x01})
	require.NoError(t, err)

	outcome, err := repository.CompareAndAdvance(
		context.Background(), commonWatermark.NamespaceProposals, candidate, replicaB,
	)

	require.NoError(t, err)
	require.Equal(t, commonWatermark.OutcomeAdvanced, outcome)
	encoded := attributeMap(t, write.ExpressionAttributeValues[":watermarks"])
	require.Contains(t, encoded, string(commonWatermark.NamespacePrevotes))
	require.Contains(t, encoded, string(commonWatermark.NamespacePrecommits))
	require.Contains(t, encoded, string(commonWatermark.NamespaceProposals))
	require.Equal(t, "11", attributeNumber(t, write.ExpressionAttributeValues[":owner_height"]))
	require.Equal(t, replicaB.String(), attributeString(t, write.ExpressionAttributeValues[":owner_replica_name"]))
	require.Equal(t, initialConditionExpression, aws.ToString(write.ConditionExpression))
	require.Equal(t, validatorIDAttribute, write.ExpressionAttributeNames["#validator_id"])
}

func TestRepository_ReadLegacyStateUsesHighestHeightOwnerAndPreservesEveryNamespace(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	replicaB := mustReplicaID(t, "replica-b")
	wantState := commonWatermark.State{
		commonWatermark.NamespacePrevotes:      testWatermark(7, 1, commonWatermark.RankFirst, "prevote"),
		commonWatermark.NamespacePrecommits:    testWatermark(8, 1, commonWatermark.RankFirst, "precommit"),
		commonWatermark.NamespaceProposals:     testWatermark(9, 1, commonWatermark.RankFirst, "proposal"),
		commonWatermark.NamespaceProposalParts: testWatermark(10, 1, commonWatermark.RankFirst, "proposal-parts"),
	}
	legacyItems := map[commonWatermark.Namespace]map[string]dynamodbTypes.AttributeValue{
		commonWatermark.NamespacePrevotes: testItem(
			"01", commonWatermark.NamespacePrevotes, wantState[commonWatermark.NamespacePrevotes],
		),
		commonWatermark.NamespacePrecommits: testOwnedItem(
			"01", commonWatermark.NamespacePrecommits,
			wantState[commonWatermark.NamespacePrecommits], replicaB.String(),
		),
		commonWatermark.NamespaceProposals: testOwnedItem(
			"01", commonWatermark.NamespaceProposals,
			wantState[commonWatermark.NamespaceProposals], replicaB.String(),
		),
		commonWatermark.NamespaceProposalParts: testOwnedItem(
			"01", commonWatermark.NamespaceProposalParts,
			wantState[commonWatermark.NamespaceProposalParts], replicaA.String(),
		),
	}
	client := &fakeDynamoDBClient{getItem: func(_ context.Context, input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
		namespace := commonWatermark.Namespace(attributeString(t, input.Key[namespaceAttribute]))
		return &dynamodb.GetItemOutput{Item: legacyItems[namespace]}, nil
	}}
	repository, err := newRepository(client, "watermarks", []byte{0x01})
	require.NoError(t, err)

	got, err := repository.readLegacyState(context.Background())

	require.NoError(t, err)
	require.Equal(t, wantState, got.state)
	require.Equal(t, commonWatermark.Ownership{
		Height:      10,
		ReplicaName: replicaA.String(),
	}, got.ownership)
}

func TestRepository_ReadLegacyStateRejectsAmbiguousHighestHeightOwner(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	replicaB := mustReplicaID(t, "replica-b")
	tests := map[string]map[commonWatermark.Namespace]map[string]dynamodbTypes.AttributeValue{
		"missing owner": {
			commonWatermark.NamespacePrevotes: testItem(
				"01", commonWatermark.NamespacePrevotes,
				testWatermark(10, 1, commonWatermark.RankFirst, "prevote"),
			),
		},
		"conflicting owners": {
			commonWatermark.NamespacePrevotes: testOwnedItem(
				"01", commonWatermark.NamespacePrevotes,
				testWatermark(10, 1, commonWatermark.RankFirst, "prevote"), replicaA.String(),
			),
			commonWatermark.NamespacePrecommits: testOwnedItem(
				"01", commonWatermark.NamespacePrecommits,
				testWatermark(10, 1, commonWatermark.RankFirst, "precommit"), replicaB.String(),
			),
		},
	}

	for name, legacyItems := range tests {
		t.Run(name, func(t *testing.T) {
			client := &fakeDynamoDBClient{getItem: func(_ context.Context, input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
				namespace := commonWatermark.Namespace(attributeString(t, input.Key[namespaceAttribute]))
				return &dynamodb.GetItemOutput{Item: legacyItems[namespace]}, nil
			}}
			repository, err := newRepository(client, "watermarks", []byte{0x01})
			require.NoError(t, err)

			_, err = repository.readLegacyState(context.Background())

			require.ErrorIs(t, err, commonWatermark.ErrWatermarkCorrupt)
		})
	}
}

func TestRepository_RejectsCrossKindPrevoteAndHeightOwnerConflict(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	replicaB := mustReplicaID(t, "replica-b")
	state := commonWatermark.State{
		commonWatermark.NamespacePrecommits: testWatermark(10, 2, commonWatermark.RankFirst, "precommit"),
	}
	reads, updates := 0, 0
	client := &fakeDynamoDBClient{
		getItem: func(context.Context, *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			reads++
			return &dynamodb.GetItemOutput{Item: testAggregateItem(
				"01", 3, state,
				commonWatermark.Ownership{Height: 10, ReplicaName: replicaA.String()},
			)}, nil
		},
		updateItem: func(context.Context, *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			updates++
			return &dynamodb.UpdateItemOutput{}, nil
		},
	}
	repository, err := newRepository(client, "watermarks", []byte{0x01})
	require.NoError(t, err)

	_, err = repository.CompareAndAdvance(
		context.Background(), commonWatermark.NamespacePrevotes,
		testWatermark(10, 1, commonWatermark.RankFirst, "prevote"), replicaA,
	)
	require.ErrorIs(t, err, commonWatermark.ErrWatermarkViolation)

	_, err = repository.CompareAndAdvance(
		context.Background(), commonWatermark.NamespaceProposals,
		testWatermark(10, 0, commonWatermark.RankFirst, "proposal"), replicaB,
	)
	require.ErrorIs(t, err, commonWatermark.ErrWatermarkOwnerConflict)
	require.Equal(t, 3, reads, "startup and each refusal must use a consistent read")
	require.Zero(t, updates)
}

func TestRepository_IdenticalRetryIsVersionFenced(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	candidate := testWatermark(10, 2, commonWatermark.RankFirst, "candidate")
	updates := 0
	client := &fakeDynamoDBClient{
		getItem: func(context.Context, *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: testAggregateItem(
				"01", 9,
				commonWatermark.State{commonWatermark.NamespacePrevotes: candidate},
				commonWatermark.Ownership{Height: 10, ReplicaName: replicaA.String()},
			)}, nil
		},
		updateItem: func(_ context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			updates++
			require.Equal(t, "9", attributeNumber(t, input.ExpressionAttributeValues[":expected_version"]))
			return &dynamodb.UpdateItemOutput{}, nil
		},
	}
	repository, err := newRepository(client, "watermarks", []byte{0x01})
	require.NoError(t, err)

	outcome, err := repository.CompareAndAdvance(
		context.Background(), commonWatermark.NamespacePrevotes, candidate, replicaA,
	)

	require.NoError(t, err)
	require.Equal(t, commonWatermark.OutcomeUnchanged, outcome)
	require.Equal(t, 1, updates)
}

func TestRepository_IdenticalRetryRejectsNewDurableOwner(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	replicaB := mustReplicaID(t, "replica-b")
	candidate := testWatermark(10, 2, commonWatermark.RankFirst, "candidate")
	initial := testAggregateItem(
		"01", 9,
		commonWatermark.State{commonWatermark.NamespacePrevotes: candidate},
		commonWatermark.Ownership{Height: 10, ReplicaName: replicaA.String()},
	)
	advanced := testAggregateItem(
		"01", 10,
		commonWatermark.State{
			commonWatermark.NamespacePrevotes:  candidate,
			commonWatermark.NamespaceProposals: testWatermark(11, 0, commonWatermark.RankFirst, "proposal"),
		},
		commonWatermark.Ownership{Height: 11, ReplicaName: replicaB.String()},
	)
	reads, updates := 0, 0
	client := &fakeDynamoDBClient{
		getItem: func(context.Context, *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			reads++
			if reads == 1 {
				return &dynamodb.GetItemOutput{Item: initial}, nil
			}
			return &dynamodb.GetItemOutput{Item: advanced}, nil
		},
		updateItem: func(context.Context, *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			updates++
			return nil, &dynamodbTypes.ConditionalCheckFailedException{Item: advanced}
		},
	}
	repository, err := newRepository(client, "watermarks", []byte{0x01})
	require.NoError(t, err)

	_, err = repository.CompareAndAdvance(
		context.Background(), commonWatermark.NamespacePrevotes, candidate, replicaA,
	)

	require.ErrorIs(t, err, commonWatermark.ErrWatermarkOwnerConflict)
	require.Equal(t, 2, reads)
	require.Equal(t, 1, updates)
}

func TestRepository_InvalidInputDoesNotCallDynamoDB(t *testing.T) {
	calls := 0
	client := &fakeDynamoDBClient{
		getItem: func(context.Context, *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			calls++
			return nil, nil
		},
	}
	repository, err := newRepository(client, "watermarks", []byte{0x01})
	require.NoError(t, err)

	_, err = repository.CompareAndAdvance(
		context.Background(), commonWatermark.NamespacePrevotes,
		testWatermark(10, 2, commonWatermark.Rank(2), "candidate"), mustReplicaID(t, "replica-a"),
	)
	require.ErrorIs(t, err, commonWatermark.ErrInvalidCandidate)

	_, err = repository.CompareAndAdvance(
		context.Background(), commonWatermark.NamespacePrevotes,
		testWatermark(10, 2, commonWatermark.RankFirst, "candidate"), replica.ID{},
	)
	require.ErrorIs(t, err, commonWatermark.ErrInvalidCandidate)
	require.Zero(t, calls)
}

func TestRepository_FailsClosedOnDynamoDBErrors(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	api4xx := &smithyHTTP.ResponseError{
		Response: &smithyHTTP.Response{Response: &http.Response{StatusCode: http.StatusBadRequest}},
		Err:      &smithy.GenericAPIError{Code: "ValidationException", Message: "bad request"},
	}
	tests := map[string]struct {
		readError         error
		updateError       error
		wantIndeterminate bool
	}{
		"read error":      {readError: errors.New("read unavailable")},
		"write 4xx":       {updateError: api4xx},
		"ambiguous write": {updateError: errors.New("connection closed"), wantIndeterminate: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := &fakeDynamoDBClient{
				getItem: func(context.Context, *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
					if tt.readError != nil {
						return nil, tt.readError
					}
					return &dynamodb.GetItemOutput{Item: testAggregateItem("01", 1, commonWatermark.State{}, commonWatermark.Ownership{})}, nil
				},
				updateItem: func(context.Context, *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
					return nil, tt.updateError
				},
			}
			repository, err := newRepository(client, "watermarks", []byte{0x01})
			require.NoError(t, err)
			_, err = repository.CompareAndAdvance(
				context.Background(), commonWatermark.NamespacePrevotes,
				testWatermark(10, 2, commonWatermark.RankFirst, "candidate"), replicaA,
			)
			require.Error(t, err)
			require.Equal(t, tt.wantIndeterminate, errors.Is(err, commonWatermark.ErrWatermarkIndeterminate))
		})
	}
}

func TestRepository_MissingDynamoDBReadResponseFailsClosed(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	repository, err := newRepository(&fakeDynamoDBClient{
		getItem: func(context.Context, *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) { return nil, nil },
	}, "watermarks", []byte{0x01})
	require.NoError(t, err)
	_, err = repository.CompareAndAdvance(context.Background(), commonWatermark.NamespacePrevotes,
		testWatermark(10, 2, commonWatermark.RankFirst, "candidate"), replicaA)
	require.Error(t, err)
}

func TestRepository_SuccessfulWriteDoesNotRequireResponseFields(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	repository, err := newRepository(&fakeDynamoDBClient{
		getItem: func(context.Context, *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: testAggregateItem("01", 1, commonWatermark.State{}, commonWatermark.Ownership{})}, nil
		},
		updateItem: func(context.Context, *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) { return nil, nil },
	}, "watermarks", []byte{0x01})
	require.NoError(t, err)

	outcome, err := repository.CompareAndAdvance(context.Background(), commonWatermark.NamespacePrevotes,
		testWatermark(10, 2, commonWatermark.RankFirst, "candidate"), replicaA)

	require.NoError(t, err)
	require.Equal(t, commonWatermark.OutcomeAdvanced, outcome)
}

func TestRepository_CorruptAggregateAndLegacyStateFailClosed(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	tests := map[string]func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error){
		"aggregate missing owner": func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: testAggregateItem("01", 1,
				commonWatermark.State{commonWatermark.NamespacePrevotes: testWatermark(10, 1, commonWatermark.RankFirst, "prevote")},
				commonWatermark.Ownership{})}, nil
		},
		"aggregate owner height mismatch": func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: testAggregateItem("01", 1,
				commonWatermark.State{commonWatermark.NamespacePrevotes: testWatermark(10, 1, commonWatermark.RankFirst, "prevote")},
				commonWatermark.Ownership{Height: 9, ReplicaName: replicaA.String()})}, nil
		},
		"legacy missing owner": func(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			if attributeString(t, input.Key[namespaceAttribute]) == string(commonWatermark.NamespacePrevotes) {
				return &dynamodb.GetItemOutput{Item: testItem("01", commonWatermark.NamespacePrevotes,
					testWatermark(10, 1, commonWatermark.RankFirst, "prevote"))}, nil
			}
			return &dynamodb.GetItemOutput{}, nil
		},
	}
	for name, getItem := range tests {
		t.Run(name, func(t *testing.T) {
			repository, err := newRepository(&fakeDynamoDBClient{getItem: func(_ context.Context, input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
				return getItem(input)
			}}, "watermarks", []byte{0x01})
			require.NoError(t, err)
			_, err = repository.CompareAndAdvance(context.Background(), commonWatermark.NamespacePrevotes,
				testWatermark(11, 1, commonWatermark.RankFirst, "candidate"), replicaA)
			require.ErrorIs(t, err, commonWatermark.ErrWatermarkCorrupt)
		})
	}
}

func TestRepository_AmbiguousCommittedWriteCanBeRetried(t *testing.T) {
	replicaA := mustReplicaID(t, "replica-a")
	candidate := testWatermark(10, 2, commonWatermark.RankFirst, "candidate")
	committed := false
	client := &fakeDynamoDBClient{
		getItem: func(context.Context, *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			if committed {
				return &dynamodb.GetItemOutput{Item: testAggregateItem("01", 2,
					commonWatermark.State{commonWatermark.NamespacePrevotes: candidate},
					commonWatermark.Ownership{Height: 10, ReplicaName: replicaA.String()})}, nil
			}
			return &dynamodb.GetItemOutput{Item: testAggregateItem("01", 1, commonWatermark.State{}, commonWatermark.Ownership{})}, nil
		},
		updateItem: func(_ context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			if !committed {
				committed = true
				return nil, context.DeadlineExceeded
			}
			if attributeNumber(t, input.ExpressionAttributeValues[":expected_version"]) == "1" {
				return nil, &dynamodbTypes.ConditionalCheckFailedException{Item: testAggregateItem(
					"01", 2,
					commonWatermark.State{commonWatermark.NamespacePrevotes: candidate},
					commonWatermark.Ownership{Height: 10, ReplicaName: replicaA.String()},
				)}
			}
			return &dynamodb.UpdateItemOutput{}, nil
		},
	}
	repository, err := newRepository(client, "watermarks", []byte{0x01})
	require.NoError(t, err)

	_, err = repository.CompareAndAdvance(context.Background(), commonWatermark.NamespacePrevotes, candidate, replicaA)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorIs(t, err, commonWatermark.ErrWatermarkIndeterminate)

	outcome, err := repository.CompareAndAdvance(context.Background(), commonWatermark.NamespacePrevotes, candidate, replicaA)
	require.NoError(t, err)
	require.Equal(t, commonWatermark.OutcomeUnchanged, outcome)
}

func TestNewRepository_ValidatesConfiguration(t *testing.T) {
	_, err := newRepository(nil, "watermarks", []byte{0x01})
	require.Error(t, err)
	_, err = newRepository(&fakeDynamoDBClient{}, " ", []byte{0x01})
	require.Error(t, err)
	_, err = newRepository(&fakeDynamoDBClient{}, "watermarks", nil)
	require.Error(t, err)
}

func TestDecodeWatermarkAndOwnerRejectMalformedState(t *testing.T) {
	valid := testItem("01", commonWatermark.NamespacePrevotes,
		testWatermark(10, 2, commonWatermark.RankFirst, "candidate"))
	tests := map[string]func(map[string]dynamodbTypes.AttributeValue){
		"negative height": func(item map[string]dynamodbTypes.AttributeValue) {
			item[heightAttribute] = &dynamodbTypes.AttributeValueMemberN{Value: "-1"}
		},
		"rank above uint8": func(item map[string]dynamodbTypes.AttributeValue) {
			item[rankAttribute] = &dynamodbTypes.AttributeValueMemberN{Value: "256"}
		},
		"short hash": func(item map[string]dynamodbTypes.AttributeValue) {
			item[messageHashAttribute] = &dynamodbTypes.AttributeValueMemberB{Value: make([]byte, 31)}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			item := make(map[string]dynamodbTypes.AttributeValue, len(valid))
			for key, value := range valid {
				item[key] = value
			}
			mutate(item)
			_, err := decodeWatermark(commonWatermark.NamespacePrevotes, item)
			require.Error(t, err)
		})
	}
	for name, item := range map[string]map[string]dynamodbTypes.AttributeValue{
		"wrong type": {ownerReplicaNameAttribute: &dynamodbTypes.AttributeValueMemberN{Value: "1"}},
		"empty":      {ownerReplicaNameAttribute: &dynamodbTypes.AttributeValueMemberS{Value: ""}},
		"whitespace": {ownerReplicaNameAttribute: &dynamodbTypes.AttributeValueMemberS{Value: "replica a"}},
		"too long":   {ownerReplicaNameAttribute: &dynamodbTypes.AttributeValueMemberS{Value: strings.Repeat("a", 256)}},
	} {
		t.Run("owner "+name, func(t *testing.T) {
			_, err := decodeOwnerReplica(item)
			require.Error(t, err)
		})
	}
}

func testWatermark(height, round uint64, rank commonWatermark.Rank, message string) commonWatermark.Watermark {
	return commonWatermark.Watermark{
		Tuple:       commonWatermark.Tuple{Height: height, Round: round, Rank: rank},
		MessageHash: commonWatermark.HashMessage([]byte(message)),
	}
}

func testItem(validatorID string, namespace commonWatermark.Namespace, stored commonWatermark.Watermark) map[string]dynamodbTypes.AttributeValue {
	return map[string]dynamodbTypes.AttributeValue{
		validatorIDAttribute: &dynamodbTypes.AttributeValueMemberS{Value: validatorID},
		namespaceAttribute:   &dynamodbTypes.AttributeValueMemberS{Value: string(namespace)},
		heightAttribute:      numberAttribute(stored.Tuple.Height),
		roundAttribute:       numberAttribute(stored.Tuple.Round),
		rankAttribute:        numberAttribute(uint64(stored.Tuple.Rank)),
		messageHashAttribute: &dynamodbTypes.AttributeValueMemberB{Value: stored.MessageHash[:]},
	}
}

func testOwnedItem(validatorID string, namespace commonWatermark.Namespace, stored commonWatermark.Watermark, owner string) map[string]dynamodbTypes.AttributeValue {
	item := testItem(validatorID, namespace, stored)
	item[ownerReplicaNameAttribute] = &dynamodbTypes.AttributeValueMemberS{Value: owner}
	return item
}

func testAggregateItem(validatorID string, version uint64, state commonWatermark.State, ownership commonWatermark.Ownership) map[string]dynamodbTypes.AttributeValue {
	item := map[string]dynamodbTypes.AttributeValue{
		validatorIDAttribute: &dynamodbTypes.AttributeValueMemberS{Value: validatorID},
		namespaceAttribute:   &dynamodbTypes.AttributeValueMemberS{Value: AggregateNamespace},
		versionAttribute:     numberAttribute(version),
		watermarksAttribute:  encodeState(state),
	}
	if ownership.ReplicaName != "" {
		item[ownerHeightAttribute] = numberAttribute(ownership.Height)
		item[ownerReplicaNameAttribute] = &dynamodbTypes.AttributeValueMemberS{Value: ownership.ReplicaName}
	}
	return item
}

func attributeString(t *testing.T, value dynamodbTypes.AttributeValue) string {
	t.Helper()
	attribute, ok := value.(*dynamodbTypes.AttributeValueMemberS)
	require.True(t, ok)
	return attribute.Value
}

func attributeNumber(t *testing.T, value dynamodbTypes.AttributeValue) string {
	t.Helper()
	attribute, ok := value.(*dynamodbTypes.AttributeValueMemberN)
	require.True(t, ok)
	return attribute.Value
}

func attributeMap(t *testing.T, value dynamodbTypes.AttributeValue) map[string]dynamodbTypes.AttributeValue {
	t.Helper()
	attribute, ok := value.(*dynamodbTypes.AttributeValueMemberM)
	require.True(t, ok)
	return attribute.Value
}

func TestRepository_ExhaustedVersionFailsClosed(t *testing.T) {
	stored := testWatermark(10, 2, commonWatermark.RankFirst, "stored")
	owner := mustReplicaID(t, "replica-a")
	for name, candidate := range map[string]commonWatermark.Watermark{
		"identical retry": stored,
		"advance":         testWatermark(11, 0, commonWatermark.RankFirst, "advance"),
	} {
		t.Run(name, func(t *testing.T) {
			client := &fakeDynamoDBClient{
				getItem: func(context.Context, *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
					return &dynamodb.GetItemOutput{Item: testAggregateItem("0102", ^uint64(0), commonWatermark.State{commonWatermark.NamespacePrevotes: stored}, commonWatermark.Ownership{Height: 10, ReplicaName: owner.String()})}, nil
				},
				updateItem: func(context.Context, *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
					t.Error("exhausted version must not wrap or write")
					return &dynamodb.UpdateItemOutput{}, nil
				},
			}
			repository, err := newRepository(client, "watermarks", []byte{1, 2})
			require.NoError(t, err)
			outcome, err := repository.CompareAndAdvance(context.Background(), commonWatermark.NamespacePrevotes, candidate, owner)
			require.ErrorIs(t, err, commonWatermark.ErrWatermarkCorrupt)
			require.Zero(t, outcome)
		})
	}
}

func TestRepository_DurableVersionRegressionFailsClosed(t *testing.T) {
	owner := mustReplicaID(t, "replica-a")
	initial := testAggregateItem("01", 9,
		commonWatermark.State{commonWatermark.NamespacePrevotes: testWatermark(10, 0, commonWatermark.RankFirst, "stored")},
		commonWatermark.Ownership{Height: 10, ReplicaName: owner.String()},
	)
	older := testAggregateItem("01", 8,
		commonWatermark.State{commonWatermark.NamespacePrevotes: testWatermark(8, 0, commonWatermark.RankFirst, "older")},
		commonWatermark.Ownership{Height: 8, ReplicaName: owner.String()},
	)
	for name, tc := range map[string]struct {
		item            map[string]dynamodbTypes.AttributeValue
		candidateHeight uint64
		conditionalRace bool
	}{
		"aggregate deleted before refusal refresh": {candidateHeight: 9},
		"older aggregate on refusal refresh":       {item: older, candidateHeight: 9},
		"older aggregate on conditional race":      {item: older, candidateHeight: 11, conditionalRace: true},
	} {
		t.Run(name, func(t *testing.T) {
			reads, writes := 0, 0
			client := &fakeDynamoDBClient{
				getItem: func(context.Context, *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
					reads++
					if reads == 1 {
						return &dynamodb.GetItemOutput{Item: initial}, nil
					}
					return &dynamodb.GetItemOutput{Item: tc.item}, nil
				},
				updateItem: func(context.Context, *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
					writes++
					if tc.conditionalRace {
						return nil, &dynamodbTypes.ConditionalCheckFailedException{Item: tc.item}
					}
					return &dynamodb.UpdateItemOutput{}, nil
				},
			}
			repository, err := newRepository(client, "watermarks", []byte{1})
			require.NoError(t, err)
			outcome, err := repository.CompareAndAdvance(context.Background(), commonWatermark.NamespacePrevotes,
				testWatermark(tc.candidateHeight, 0, commonWatermark.RankFirst, "candidate"), owner)
			require.ErrorIs(t, err, commonWatermark.ErrWatermarkCorrupt)
			require.Zero(t, outcome)
			if tc.conditionalRace {
				require.Equal(t, 1, writes, "must not retry from regressed state")
			} else {
				require.Zero(t, writes, "must not write from regressed state")
			}
		})
	}
}
