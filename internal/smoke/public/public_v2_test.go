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

//go:build smoke

package smoke

import (
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	watermarkRepository "github.com/circlefin/arc-remote-signer/internal/app/repository/watermark"
	"github.com/circlefin/arc-remote-signer/internal/common/crypto"
	enclaveCrypto "github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	"github.com/circlefin/arc-remote-signer/internal/smoke/provider/proxy"
	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	restartVerificationEnv = "SMOKE_VERIFY_RESTART"
	smokeWatermarkHeight   = uint64(100)
	restartWatermarkHeight = uint64(200)
)

func signerV2AWSConfig(t *testing.T) aws.Config {
	t.Helper()
	options := []func(*awsConfig.LoadOptions) error{awsConfig.WithRegion("us-east-1")}
	if !expectNitroAttestation {
		options = append(options,
			awsConfig.WithBaseEndpoint("http://localhost:4566"),
			awsConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
		)
	}
	cfg, err := awsConfig.LoadDefaultConfig(context.Background(), options...)
	require.NoError(t, err)
	return cfg
}

var signerV2Namespaces = []struct {
	name string
	kind signerv2.MessageKind
}{
	{"prevotes", signerv2.MessageKind_MESSAGE_KIND_PREVOTE},
	{"precommits", signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT},
	{"proposals", signerv2.MessageKind_MESSAGE_KIND_PROPOSAL},
	{"proposal-parts", signerv2.MessageKind_MESSAGE_KIND_PROPOSAL_PARTS},
}

type watermarkSnapshot map[string]map[string]dynamodbTypes.AttributeValue

type watermarkTestStore struct {
	client      *dynamodb.Client
	validatorID string
}

func (s watermarkTestStore) key(namespace string) map[string]dynamodbTypes.AttributeValue {
	return map[string]dynamodbTypes.AttributeValue{
		"validator_id": &dynamodbTypes.AttributeValueMemberS{Value: s.validatorID},
		"namespace":    &dynamodbTypes.AttributeValueMemberS{Value: namespace},
	}
}

func (s watermarkTestStore) snapshot(t *testing.T) watermarkSnapshot {
	t.Helper()
	snapshot := make(watermarkSnapshot)
	namespaces := []string{watermarkRepository.AggregateNamespace}
	for _, ns := range signerV2Namespaces {
		namespaces = append(namespaces, ns.name)
	}
	for _, namespace := range namespaces {
		output, err := s.client.GetItem(context.Background(), &dynamodb.GetItemInput{TableName: aws.String(watermarkRepository.TableName), Key: s.key(namespace), ConsistentRead: aws.Bool(true)})
		require.NoError(t, err, "snapshot %s", namespace)
		snapshot[namespace] = output.Item
	}
	return snapshot
}

func storedSignerV2Number(t *testing.T, item map[string]dynamodbTypes.AttributeValue, name string) uint64 {
	t.Helper()
	attribute, ok := item[name].(*dynamodbTypes.AttributeValueMemberN)
	require.True(t, ok, "DynamoDB watermark %s must be a number", name)
	value, err := strconv.ParseUint(attribute.Value, 10, 64)
	require.NoError(t, err, "parse DynamoDB watermark %s", name)
	return value
}

func requireSignerV2RetryState(t *testing.T, before, after watermarkSnapshot) {
	t.Helper()
	beforeState := before[watermarkRepository.AggregateNamespace]
	afterState := after[watermarkRepository.AggregateNamespace]
	require.Equal(t, storedSignerV2Number(t, beforeState, "version")+1, storedSignerV2Number(t, afterState, "version"))
	withoutFence := maps.Clone(after)
	withoutFence[watermarkRepository.AggregateNamespace] = maps.Clone(afterState)
	withoutFence[watermarkRepository.AggregateNamespace]["version"] = beforeState["version"]
	require.Equal(t, before, withoutFence, "exact retry may change only the version fence")
}

func storedSignerV2Kind(t *testing.T, snapshot watermarkSnapshot, namespace string) map[string]dynamodbTypes.AttributeValue {
	t.Helper()
	item := snapshot[watermarkRepository.AggregateNamespace]
	if len(item) == 0 {
		return snapshot[namespace]
	}
	watermarks, ok := item["watermarks"].(*dynamodbTypes.AttributeValueMemberM)
	require.True(t, ok, "aggregate watermarks must be a map")
	if value, exists := watermarks.Value[namespace]; exists {
		stored, ok := value.(*dynamodbTypes.AttributeValueMemberM)
		require.True(t, ok, "stored watermark must be a map")
		return stored.Value
	}
	return nil
}

func nextSignerV2Height(t *testing.T, snapshot watermarkSnapshot) uint64 {
	t.Helper()
	next := smokeWatermarkHeight
	for _, ns := range signerV2Namespaces {
		item := storedSignerV2Kind(t, snapshot, ns.name)
		if len(item) == 0 {
			continue
		}
		height := storedSignerV2Number(t, item, "height")
		require.NotEqual(t, ^uint64(0), height, "DynamoDB watermark height cannot advance")
		if height >= next {
			next = height + 1
		}
	}
	return next
}

type signerV2Fixture struct {
	client    *proxy.Provider
	publicKey []byte
	store     watermarkTestStore
}

func newSignerV2Fixture(t *testing.T) *signerV2Fixture {
	t.Helper()
	client, err := proxy.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close signer client: %v", err)
		}
	})
	publicKey, err := client.PublicKeyV2(context.Background())
	require.NoError(t, err)
	require.Len(t, publicKey.GetPublicKey(), 32)
	return &signerV2Fixture{
		client: client, publicKey: publicKey.GetPublicKey(),
		store: watermarkTestStore{client: dynamodb.NewFromConfig(signerV2AWSConfig(t)), validatorID: hex.EncodeToString(publicKey.GetPublicKey())},
	}
}

func TestPublicV2(t *testing.T) {
	fixture := newSignerV2Fixture(t)
	if os.Getenv(restartVerificationEnv) == "true" {
		testSignerV2Restart(t, fixture)
		return
	}

	t.Run("public_key", func(t *testing.T) {
		v1, err := fixture.client.PublicKey(context.Background())
		require.NoError(t, err)
		v2, err := fixture.client.PublicKeyV2(context.Background())
		require.NoError(t, err)
		require.Len(t, v2.GetPublicKey(), 32)
		require.Equal(t, v1.GetPublicKey(), v2.GetPublicKey())
		require.Equal(t, v1.GetAttestationDocument(), v2.GetAttestationDocument())
	})

	for _, ns := range signerV2Namespaces {
		t.Run(ns.name, func(t *testing.T) {
			height := nextSignerV2Height(t, fixture.store.snapshot(t))
			request := signerV2Request(ns.kind, height, 1)
			first := requireSignerV2Signature(t, fixture, request)
			beforeRetry := fixture.store.snapshot(t)
			require.Equal(t, first, requireSignerV2Signature(t, fixture, request))
			afterRetry := fixture.store.snapshot(t)
			requireSignerV2RetryState(t, beforeRetry, afterRetry)
			beforeRetry = afterRetry

			conflict := signerV2Request(ns.kind, height, 1)
			conflict.Message = []byte("conflicting bytes")
			_, err := fixture.client.SignV2(context.Background(), conflict)
			requireSignerV2Error(t, err, codes.FailedPrecondition, "watermark violation")

			_, err = fixture.client.SignV2(context.Background(), signerV2Request(ns.kind, height-1, 2))
			requireSignerV2Error(t, err, codes.OutOfRange, "watermark stale")
			_, err = fixture.client.SignV2(context.Background(), signerV2Request(ns.kind, height, 0))
			requireSignerV2Error(t, err, codes.OutOfRange, "watermark stale")
			require.Equal(t, beforeRetry, fixture.store.snapshot(t))

			ownerConflict := signerV2Request(ns.kind, height, 2)
			ownerConflict.ReplicaName = "validator-01-b"
			beforeConflict := fixture.store.snapshot(t)
			_, err = fixture.client.SignV2(context.Background(), ownerConflict)
			requireSignerV2Error(t, err, codes.Aborted, "other node signed")
			require.Equal(t, beforeConflict, fixture.store.snapshot(t))
		})
	}

	t.Run("aggregate_ordering", func(t *testing.T) {
		height := nextSignerV2Height(t, fixture.store.snapshot(t))
		requireSignerV2Signature(t, fixture, signerV2Request(signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT, height, 2))
		before := fixture.store.snapshot(t)
		for _, kind := range []signerv2.MessageKind{
			signerv2.MessageKind_MESSAGE_KIND_PREVOTE,
			signerv2.MessageKind_MESSAGE_KIND_PROPOSAL,
		} {
			_, err := fixture.client.SignV2(context.Background(), signerV2Request(kind, height, 2))
			requireSignerV2Error(t, err, codes.FailedPrecondition, "watermark violation")
		}
		ownerConflict := signerV2Request(signerv2.MessageKind_MESSAGE_KIND_PROPOSAL_PARTS, height, 2)
		ownerConflict.ReplicaName = "validator-01-b"
		_, err := fixture.client.SignV2(context.Background(), ownerConflict)
		requireSignerV2Error(t, err, codes.Aborted, "other node signed")
		require.Equal(t, before, fixture.store.snapshot(t))
	})

	for _, kind := range []signerv2.MessageKind{
		signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF,
		signerv2.MessageKind_MESSAGE_KIND_TELEMETRY,
		signerv2.MessageKind_MESSAGE_KIND_DELEGATION,
	} {
		t.Run(kind.String(), func(t *testing.T) {
			before := fixture.store.snapshot(t)
			for _, ns := range signerV2Namespaces {
				require.NotEmpty(t, storedSignerV2Kind(t, before, ns.name))
			}
			request := &signerv2.SignRequest{
				Message:     []byte("validator proof"),
				Metadata:    &signerv2.SigningMetadata{Kind: kind},
				ReplicaName: "validator-01-a",
			}
			if kind == signerv2.MessageKind_MESSAGE_KIND_TELEMETRY {
				request.Message = append([]byte("arc/telemetry/v1\x00"), make([]byte, 32)...)
			}
			if kind == signerv2.MessageKind_MESSAGE_KIND_DELEGATION {
				request.Message = make([]byte, 130)
				copy(request.Message, []byte("arc/auth/v1\x00\x09arc-boost"))
			}
			requireSignerV2Signature(t, fixture, request)
			require.Equal(t, before, fixture.store.snapshot(t), "tuple-less signing must preserve aggregate and legacy state")
		})
	}

	for _, invalid := range invalidSignerV2Requests() {
		t.Run("invalid/"+invalid.name, func(t *testing.T) {
			before := fixture.store.snapshot(t)
			_, err := fixture.client.SignV2(context.Background(), invalid.request)
			requireSignerV2Error(t, err, codes.InvalidArgument, invalid.errorMessage())
			require.Equal(t, before, fixture.store.snapshot(t))
		})
	}

	for _, ns := range signerV2Namespaces {
		restartHeight := nextSignerV2Height(t, fixture.store.snapshot(t))
		if restartHeight < restartWatermarkHeight {
			restartHeight = restartWatermarkHeight
		}
		requireSignerV2Signature(t, fixture, signerV2Request(ns.kind, restartHeight, 0))
	}
}

func testSignerV2Restart(t *testing.T, fixture *signerV2Fixture) {
	for _, ns := range signerV2Namespaces {
		t.Run(ns.name, func(t *testing.T) {
			before := fixture.store.snapshot(t)
			stored := storedSignerV2Kind(t, before, ns.name)
			require.NotEmpty(t, stored, "restart must recover the same validator's durable state")
			restartHeight := storedSignerV2Number(t, stored, "height")
			require.Zero(t, storedSignerV2Number(t, stored, "round"))

			_, err := fixture.client.SignV2(context.Background(), signerV2Request(ns.kind, restartHeight-1, 0))
			requireSignerV2Error(t, err, codes.OutOfRange, "watermark stale")
			requireSignerV2Signature(t, fixture, signerV2Request(ns.kind, restartHeight, 0))
			afterRetry := fixture.store.snapshot(t)
			requireSignerV2RetryState(t, before, afterRetry)
			before = afterRetry

			conflict := signerV2Request(ns.kind, restartHeight, 0)
			conflict.Message = []byte("conflict after restart")
			_, err = fixture.client.SignV2(context.Background(), conflict)
			requireSignerV2Error(t, err, codes.FailedPrecondition, "watermark violation")
			require.Equal(t, before, fixture.store.snapshot(t))
		})
	}
	for _, ns := range signerV2Namespaces {
		requireSignerV2Signature(t, fixture, signerV2Request(ns.kind, nextSignerV2Height(t, fixture.store.snapshot(t)), 0))
	}
}

func signerV2Request(kind signerv2.MessageKind, height, round uint64) *signerv2.SignRequest {
	return &signerv2.SignRequest{
		Message: []byte(fmt.Sprintf("smoke %s %d %d", kind, height, round)), ReplicaName: "validator-01-a",
		Metadata: &signerv2.SigningMetadata{Kind: kind, Height: proto.Uint64(height), Round: proto.Uint64(round)},
	}
}

func requireSignerV2Error(t *testing.T, err error, code codes.Code, message string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, code, status.Code(err))
	require.Equal(t, message, status.Convert(err).Message())
}

func requireSignerV2Signature(t *testing.T, f *signerV2Fixture, request *signerv2.SignRequest) []byte {
	t.Helper()
	response, err := f.client.SignV2(context.Background(), request)
	require.NoError(t, err)
	require.NotEmpty(t, response.GetSignature())
	valid, err := enclaveCrypto.VerifySignedMessage(crypto.AlgorithmEd25519, response.GetSignature(), request.GetMessage(), f.publicKey)
	require.NoError(t, err)
	require.True(t, valid, "signature must verify against the exact request bytes")
	return response.GetSignature()
}

type invalidSignerV2Request struct {
	name        string
	request     *signerv2.SignRequest
	wantMessage string
}

func (r invalidSignerV2Request) errorMessage() string {
	if r.wantMessage != "" {
		return r.wantMessage
	}
	return "invalid watermark candidate"
}

func invalidSignerV2Requests() []invalidSignerV2Request {
	invalid := []struct {
		name        string
		wantMessage string
		mutate      func(*signerv2.SignRequest)
	}{
		{name: "empty_message", mutate: func(r *signerv2.SignRequest) { r.Message = nil }},
		{name: "missing_metadata", mutate: func(r *signerv2.SignRequest) { r.Metadata = nil }},
		{name: "unspecified_kind", mutate: func(r *signerv2.SignRequest) { r.Metadata.Kind = signerv2.MessageKind_MESSAGE_KIND_UNSPECIFIED }},
		{name: "unknown_kind", mutate: func(r *signerv2.SignRequest) { r.Metadata.Kind = signerv2.MessageKind(99) }},
		{name: "missing_height", mutate: func(r *signerv2.SignRequest) { r.Metadata.Height = nil }},
		{name: "zero_height", mutate: func(r *signerv2.SignRequest) { r.Metadata.Height = proto.Uint64(0) }},
		{name: "missing_round", mutate: func(r *signerv2.SignRequest) { r.Metadata.Round = nil }},
		{name: "proof_with_tuple", mutate: func(r *signerv2.SignRequest) { r.Metadata.Kind = signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF }},
		{name: "telemetry_with_tuple", mutate: func(r *signerv2.SignRequest) { r.Metadata.Kind = signerv2.MessageKind_MESSAGE_KIND_TELEMETRY }},
		{name: "delegation_with_tuple", mutate: func(r *signerv2.SignRequest) { r.Metadata.Kind = signerv2.MessageKind_MESSAGE_KIND_DELEGATION }},
		{name: "empty_replica", wantMessage: "invalid replica name", mutate: func(r *signerv2.SignRequest) { r.ReplicaName = "" }},
	}
	var requests []invalidSignerV2Request
	for _, input := range invalid {
		request := signerV2Request(signerv2.MessageKind_MESSAGE_KIND_PREVOTE, smokeWatermarkHeight+1, 0)
		input.mutate(request)
		requests = append(requests, invalidSignerV2Request{name: input.name, request: request, wantMessage: input.wantMessage})
	}
	for _, payload := range []struct {
		name    string
		message []byte
	}{
		{"telemetry_short", []byte("arc/telemetry/v1\x00")},
		{"telemetry_wrong_prefix", make([]byte, 49)},
		{"telemetry_long", append([]byte("arc/telemetry/v1\x00"), make([]byte, 33)...)},
	} {
		requests = append(requests, invalidSignerV2Request{name: payload.name, request: &signerv2.SignRequest{
			Message: payload.message, ReplicaName: "validator-01-a", Metadata: &signerv2.SigningMetadata{Kind: signerv2.MessageKind_MESSAGE_KIND_TELEMETRY},
		}})
	}
	return requests
}
