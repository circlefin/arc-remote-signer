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

package enclave

import (
	"context"
	"net"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awskms"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/keystore"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/stretchr/testify/require"
)

// LocalStack fixture values mirror the awskms integration test
// (internal/enclave/provider/awskms/awskms_integration_test.go) and the docker-compose
// at deployments/docker-compose.yaml. The KMS key alias is seeded by
// deployments/localstack_scripts/create-kms-keys.sh.
const (
	localstackEndpoint   = "http://localhost:4566"
	localstackKmsArn     = "arn:aws:kms:us-east-1:000000000000:alias/dev-multi-region-crypto"
	localstackInvalidArn = "arn:aws:kms:us-east-1:000000000000:alias/does-not-exist"
)

// newLocalstackFactory returns an awskms.Factory that wires a real plaintext
// provider against LocalStack. It matches the development path while avoiding
// the host-side proxy processes. LocalStack does not support Nitro
// RecipientInfo.
func newLocalstackFactory(t *testing.T) awskms.Factory {
	t.Helper()
	return func(callCtx context.Context, awsCfg aws.Config, arns []string) (awskms.Provider, error) {
		return awskms.NewForDevelopment(
			callCtx,
			&awskms.Config{Arns: arns, ConnectTimeout: 3000},
			awsCfg,
		)
	}
}

func validIntegrationReq(t *testing.T, arn string) *pb.InitializeRequest {
	t.Helper()
	return &pb.InitializeRequest{
		Credentials: &pb.AwsCredentials{
			AccessKeyId:     "test",
			SecretAccessKey: "test",
			SessionToken:    "test",
			Region:          "us-east-1",
		},
		KmsKeyArns:           []string{arn},
		KmsLocalstackEnabled: true,
	}
}

// TestNewRunInit_Integration_HappyPath exercises the full runInit
// closure against LocalStack: awskms.BuildConfig produces an aws.Config that
// points at LocalStack, the factory builds a real KMS provider, and
// GenerateDataKey returns successfully.
//
// This test points awsproxyEndpoint at LocalStack. It exercises a direct
// SDK-to-LocalStack dial instead of the production awsproxy(TCP) ->
// vsockproxy -> LocalStack chain. That keeps the runInit logic test
// hermetic (no proxy processes to stand up). The proxied chain itself is
// covered end-to-end elsewhere in CI: the compose smoke job (make test-all
// -> up -> smoke.sh, which starts the host app and Initializes the enclave
// through the wired proxies) and the dedicated smoke_eif job
// (scripts/smoke-eif.sh on a real Nitro runner).
func TestNewRunInit_Integration_HappyPath(t *testing.T) {
	s := newServiceForTest(t, false, keystore.New(), nil, newLocalstackFactory(t), localstackEndpoint)
	err := s.runInit(context.Background(), validIntegrationReq(t, localstackKmsArn))
	require.NoError(t, err, "runInit must succeed against LocalStack with a valid ARN")
}

// TestNewRunInit_Integration_InvalidArn verifies that runInit surfaces a
// non-nil error when LocalStack rejects the ARN. The error is returned
// raw — mapping to a gRPC status happens in runInitStatusError, not
// inside runInit.
func TestNewRunInit_Integration_InvalidArn(t *testing.T) {
	s := newServiceForTest(t, false, keystore.New(), nil, newLocalstackFactory(t), localstackEndpoint)
	err := s.runInit(context.Background(), validIntegrationReq(t, localstackInvalidArn))
	require.Error(t, err, "runInit must propagate KMS errors when the ARN is unknown")
}

// TestNewRunInit_Integration_InvalidEndpoint verifies that runInit
// surfaces a transport error when awsproxy is unreachable. We point at
// 127.0.0.1:65535 which is essentially never bound, so the SDK's HTTP
// dial fails fast with connection refused. The error must satisfy
// net.Error somewhere in the wrap chain so awskms.StatusFromError's net.Error
// branch will translate it to codes.Unavailable in production.
func TestNewRunInit_Integration_InvalidEndpoint(t *testing.T) {
	s := newServiceForTest(t, false, keystore.New(), nil, newLocalstackFactory(t), "http://127.0.0.1:65535")
	err := s.runInit(context.Background(), validIntegrationReq(t, localstackKmsArn))
	require.Error(t, err, "runInit must surface a transport error when the endpoint is unreachable")
	var netErr net.Error
	require.ErrorAs(t, err, &netErr,
		"SDK transport failure must wrap a net.Error so awskms.StatusFromError's net.Error branch fires in production")
}

// TestService_Envelope_Integration_GenerateThenSign generates a key
// in-enclave via a real LocalStack KMS GenerateDataKey, then signs with the
// returned SecretEnvelope end to end and verifies the signature.
func TestService_Envelope_Integration_GenerateThenSign(t *testing.T) {
	ctx := context.Background()
	s := newServiceForTest(t, false, keystore.New(), nil, newLocalstackFactory(t), localstackEndpoint)
	_, err := s.Initialize(ctx, validIntegrationReq(t, localstackKmsArn))
	require.NoError(t, err, "Initialize must succeed against LocalStack")

	gen, err := s.GenerateKey(ctx, &pb.GenerateKeyRequest{Algorithm: pb.Algorithm_ALGORITHM_ED25519})
	require.NoError(t, err)
	require.NotNil(t, gen.SecretEnvelope, "GenerateKey must return a SecretEnvelope")

	msg := []byte("integration-message")
	sig, err := s.SignMessage(ctx, &pb.SignMessageRequest{
		SecretEnvelope: gen.SecretEnvelope,
		Message:        msg,
	})
	require.NoError(t, err)
	require.NotEmpty(t, sig.Signature)

	ok, err := crypto.VerifySignedMessage(crypto.AlgorithmEd25519, sig.Signature, msg, gen.PublicKey)
	require.NoError(t, err)
	require.True(t, ok, "signature must verify against the generated public key")
}
