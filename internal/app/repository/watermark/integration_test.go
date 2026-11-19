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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsSdkConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/circlefin/arc-remote-signer/internal/common/replica"
	commonWatermark "github.com/circlefin/arc-remote-signer/internal/common/watermark"
	"github.com/stretchr/testify/require"
)

const (
	testAWSRegion          = "us-east-1"
	testLocalStackEndpoint = "http://localhost:4566"
)

func TestIntegrationTableConfiguration(t *testing.T) {
	client := dynamodb.NewFromConfig(integrationAWSConfig(t))

	output, err := client.DescribeTable(context.Background(), &dynamodb.DescribeTableInput{
		TableName: aws.String(TableName),
	})
	require.NoError(t, err)
	require.NotNil(t, output.Table)
	require.Equal(t, dynamodbTypes.TableStatusActive, output.Table.TableStatus)
	require.NotNil(t, output.Table.BillingModeSummary)
	require.Equal(t, dynamodbTypes.BillingModePayPerRequest, output.Table.BillingModeSummary.BillingMode)
	require.True(t, aws.ToBool(output.Table.DeletionProtectionEnabled))
	require.ElementsMatch(t, []dynamodbTypes.KeySchemaElement{
		{AttributeName: aws.String(validatorIDAttribute), KeyType: dynamodbTypes.KeyTypeHash},
		{AttributeName: aws.String(namespaceAttribute), KeyType: dynamodbTypes.KeyTypeRange},
	}, output.Table.KeySchema)
	require.ElementsMatch(t, []dynamodbTypes.AttributeDefinition{
		{AttributeName: aws.String(validatorIDAttribute), AttributeType: dynamodbTypes.ScalarAttributeTypeS},
		{AttributeName: aws.String(namespaceAttribute), AttributeType: dynamodbTypes.ScalarAttributeTypeS},
	}, output.Table.AttributeDefinitions)
}

func TestIntegrationRepositoryCompareAndAdvance(t *testing.T) {
	cfg := integrationAWSConfig(t)
	repository, err := New(cfg, randomPublicKey(t))
	require.NoError(t, err)
	cleanupRepository(t, dynamodb.NewFromConfig(cfg), repository)

	replicaA := mustReplicaID(t, "replica-a")
	replicaB := mustReplicaID(t, "replica-b")
	ctx := context.Background()

	first := testWatermark(10, 2, commonWatermark.RankFirst, "first")
	second := testWatermark(11, 0, commonWatermark.RankFirst, "second")

	outcome, err := repository.CompareAndAdvance(ctx, commonWatermark.NamespacePrevotes, first, replicaA)
	require.NoError(t, err)
	require.Equal(t, commonWatermark.OutcomeAdvanced, outcome)

	outcome, err = repository.CompareAndAdvance(ctx, commonWatermark.NamespacePrevotes, first, replicaA)
	require.NoError(t, err)
	require.Equal(t, commonWatermark.OutcomeUnchanged, outcome)

	outcome, err = repository.CompareAndAdvance(ctx, commonWatermark.NamespacePrevotes, second, replicaA)
	require.NoError(t, err)
	require.Equal(t, commonWatermark.OutcomeAdvanced, outcome)

	_, err = repository.CompareAndAdvance(
		ctx,
		commonWatermark.NamespacePrevotes,
		testWatermark(9, 20, commonWatermark.RankFirst, "stale"),
		replicaA,
	)
	require.ErrorIs(t, err, commonWatermark.ErrWatermarkStale)

	_, err = repository.CompareAndAdvance(
		ctx,
		commonWatermark.NamespacePrevotes,
		testWatermark(11, 0, commonWatermark.RankFirst, "conflict"),
		replicaA,
	)
	require.ErrorIs(t, err, commonWatermark.ErrWatermarkViolation)

	_, err = repository.CompareAndAdvance(
		ctx,
		commonWatermark.NamespacePrevotes,
		testWatermark(11, 1, commonWatermark.RankFirst, "replica-b-msg"),
		replicaB,
	)
	require.ErrorIs(t, err, commonWatermark.ErrWatermarkOwnerConflict)

	outcome, err = repository.CompareAndAdvance(
		ctx,
		commonWatermark.NamespacePrevotes,
		testWatermark(12, 0, commonWatermark.RankFirst, "height-12-msg"),
		replicaB,
	)
	require.NoError(t, err)
	require.Equal(t, commonWatermark.OutcomeAdvanced, outcome)

	_, err = repository.CompareAndAdvance(
		ctx,
		commonWatermark.NamespacePrevotes,
		testWatermark(11, 2, commonWatermark.RankFirst, "replica-a-lagging"),
		replicaA,
	)
	require.ErrorIs(t, err, commonWatermark.ErrWatermarkOwnerConflict)
}

func TestIntegrationRepositoryHeightOwnershipAcrossNamespaces(t *testing.T) {
	cfg := integrationAWSConfig(t)
	repository, err := New(cfg, randomPublicKey(t))
	require.NoError(t, err)
	client := dynamodb.NewFromConfig(cfg)
	cleanupRepository(t, client, repository)

	replicaA := mustReplicaID(t, "replica-a")
	replicaB := mustReplicaID(t, "replica-b")
	ctx := context.Background()

	outcome, err := repository.CompareAndAdvance(
		ctx,
		commonWatermark.NamespacePrevotes,
		testWatermark(10, 0, commonWatermark.RankFirst, "prevote-10"),
		replicaA,
	)
	require.NoError(t, err)
	require.Equal(t, commonWatermark.OutcomeAdvanced, outcome)

	_, err = repository.CompareAndAdvance(
		ctx,
		commonWatermark.NamespacePrecommits,
		testWatermark(10, 0, commonWatermark.RankFirst, "precommit-10"),
		replicaB,
	)
	require.ErrorIs(t, err, commonWatermark.ErrWatermarkOwnerConflict)

	_, err = repository.CompareAndAdvance(
		ctx,
		commonWatermark.NamespaceProposals,
		testWatermark(10, 0, commonWatermark.RankFirst, "prop-10"),
		replicaB,
	)
	require.ErrorIs(t, err, commonWatermark.ErrWatermarkOwnerConflict)

	outcome, err = repository.CompareAndAdvance(
		ctx,
		commonWatermark.NamespacePrecommits,
		testWatermark(10, 0, commonWatermark.RankFirst, "precommit-10"),
		replicaA,
	)
	require.NoError(t, err)
	require.Equal(t, commonWatermark.OutcomeAdvanced, outcome)

	_, err = repository.CompareAndAdvance(
		ctx,
		commonWatermark.NamespacePrevotes,
		testWatermark(10, 1, commonWatermark.RankFirst, "prevote-10-b"),
		replicaB,
	)
	require.ErrorIs(t, err, commonWatermark.ErrWatermarkOwnerConflict)

	outcome, err = repository.CompareAndAdvance(
		ctx,
		commonWatermark.NamespacePrecommits,
		testWatermark(10, 1, commonWatermark.RankFirst, "precommit-10-a"),
		replicaA,
	)
	require.NoError(t, err)
	require.Equal(t, commonWatermark.OutcomeAdvanced, outcome)
}

func TestIntegrationRepositoryFoldsLegacyState(t *testing.T) {
	cfg := integrationAWSConfig(t)
	client := dynamodb.NewFromConfig(cfg)
	publicKey := randomPublicKey(t)
	repository, err := newRepository(client, TableName, publicKey)
	require.NoError(t, err)
	cleanupRepository(t, client, repository)

	ctx := context.Background()
	replicaA := mustReplicaID(t, "replica-a")

	legacyState := commonWatermark.State{
		commonWatermark.NamespacePrevotes:      testWatermark(7, 0, commonWatermark.RankFirst, "legacy-prevote"),
		commonWatermark.NamespacePrecommits:    testWatermark(8, 0, commonWatermark.RankFirst, "legacy-precommit"),
		commonWatermark.NamespaceProposals:     testWatermark(9, 0, commonWatermark.RankFirst, "legacy-proposal"),
		commonWatermark.NamespaceProposalParts: testWatermark(10, 0, commonWatermark.RankFirst, "legacy-proposal-parts"),
	}
	for namespace, stored := range legacyState {
		_, err = client.PutItem(ctx, &dynamodb.PutItemInput{
			TableName: aws.String(TableName),
			Item: testOwnedItem(
				repository.validatorID,
				namespace,
				stored,
				replicaA.String(),
			),
		})
		require.NoError(t, err)
	}
	repository, err = New(cfg, publicKey)
	require.NoError(t, err)

	candidate := testWatermark(11, 1, commonWatermark.RankFirst, "new-proposal-parts")
	outcome, err := repository.CompareAndAdvance(
		ctx, commonWatermark.NamespaceProposalParts, candidate, replicaA,
	)
	require.NoError(t, err)
	require.Equal(t, commonWatermark.OutcomeAdvanced, outcome)

	legacyState[commonWatermark.NamespaceProposalParts] = candidate
	requireStoredState(t, client, repository, legacyState, replicaA.String())
}

func TestIntegrationRepositoryConcurrentConflictAllowsOneCandidate(t *testing.T) {
	cfg := integrationAWSConfig(t)
	publicKey := randomPublicKey(t)
	repositoryA, err := New(cfg, publicKey)
	require.NoError(t, err)
	repositoryB, err := New(cfg, publicKey)
	require.NoError(t, err)
	cleanupRepository(t, dynamodb.NewFromConfig(cfg), repositoryA)

	replicaA := mustReplicaID(t, "replica-a")
	replicaB := mustReplicaID(t, "replica-b")

	type req struct {
		candidate commonWatermark.Watermark
		replica   replica.ID
	}
	requests := []req{
		{candidate: testWatermark(20, 0, commonWatermark.RankFirst, "candidate-a"), replica: replicaA},
		{candidate: testWatermark(20, 0, commonWatermark.RankFirst, "candidate-b"), replica: replicaB},
	}
	repositories := []*Repository{repositoryA, repositoryB}

	start := make(chan struct{})
	results := make(chan compareAndAdvanceResult, 2)
	for index, request := range requests {
		go func(repository *Repository, request req) {
			<-start
			outcome, compareErr := repository.CompareAndAdvance(
				context.Background(),
				commonWatermark.NamespacePrevotes,
				request.candidate,
				request.replica,
			)
			results <- compareAndAdvanceResult{outcome: outcome, err: compareErr}
		}(repositories[index], request)
	}
	close(start)

	var advanced, conflicts int
	for range 2 {
		result := <-results
		switch {
		case result.err == nil && result.outcome == commonWatermark.OutcomeAdvanced:
			advanced++
		case errors.Is(result.err, commonWatermark.ErrWatermarkOwnerConflict):
			conflicts++
		default:
			t.Fatalf("unexpected compare-and-advance result: outcome=%d err=%v", result.outcome, result.err)
		}
	}
	require.Equal(t, 1, advanced)
	require.Equal(t, 1, conflicts)
}

type compareAndAdvanceResult struct {
	outcome commonWatermark.Outcome
	err     error
}

func requireStoredState(
	t *testing.T,
	client *dynamodb.Client,
	repository *Repository,
	want commonWatermark.State,
	wantOwner string,
) {
	t.Helper()

	output, err := client.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(TableName),
		Key:       repository.key(AggregateNamespace),
	})
	require.NoError(t, err)
	storedState, err := decodeStoredState(output.Item)
	require.NoError(t, err)
	require.Equal(t, want, storedState.state)
	require.Equal(t, wantOwner, storedState.ownership.ReplicaName)
}

func cleanupRepository(
	t *testing.T,
	client *dynamodb.Client,
	repository *Repository,
) {
	t.Helper()
	t.Cleanup(func() {
		for _, namespace := range append(legacyNamespaces[:], commonWatermark.Namespace(AggregateNamespace)) {
			_, err := client.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
				TableName: aws.String(repository.tableName),
				Key:       repository.key(string(namespace)),
			})
			if err != nil {
				t.Errorf("delete integration watermark %s: %v", namespace, err)
			}
		}
	})
}

func integrationAWSConfig(t *testing.T) aws.Config {
	t.Helper()

	cfg, err := awsSdkConfig.LoadDefaultConfig(
		context.Background(),
		awsSdkConfig.WithRegion(testAWSRegion),
		awsSdkConfig.WithBaseEndpoint(testLocalStackEndpoint),
		awsSdkConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	require.NoError(t, err)
	return cfg
}

func randomPublicKey(t *testing.T) []byte {
	t.Helper()

	publicKey := make([]byte, 32)
	_, err := rand.Read(publicKey)
	require.NoError(t, err)
	return publicKey
}
