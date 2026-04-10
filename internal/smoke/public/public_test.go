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

// Package smoke is used to run tests for the enclave signer service endpoints.
package smoke

import (
	"context"
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/crypto"
	enclaveCrypto "github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	"github.com/circlefin/arc-remote-signer/internal/smoke/provider/proxy"
	pb "github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestSuite is the test suite for smoke tests.

type TestSuite struct {
	suite.Suite

	proxyPvd *proxy.Provider

	publicKey []byte
}

// SetupSuite sets up the test suite by creating and connecting the test client.

func (suite *TestSuite) SetupSuite() {
	proxyPvd, err := proxy.New()
	suite.Require().NoError(err, "Failed to create smoke test client")
	suite.proxyPvd = proxyPvd

	// get public key
	res, err := suite.proxyPvd.PublicKey(context.Background())
	suite.Require().NoError(err, "Failed to get public key")
	suite.Require().NotNil(res.PublicKey, "Public key is nil")
	suite.publicKey = res.PublicKey
}

// TearDownSuite tears down the test suite by closing the client connection.

func (suite *TestSuite) TearDownSuite() {
	suite.Require().NoError(suite.proxyPvd.Close())
}

// TestPublicKey tests the PublicKey gRPC endpoint.

func (suite *TestSuite) TestPublicKey() {
	ctx := context.Background()

	result, err := suite.proxyPvd.PublicKey(ctx)
	suite.Require().NoError(err, "PublicKey endpoint failed")
	suite.Require().NotNil(result, "PublicKey response is nil")
	suite.Require().NotEmpty(result.PublicKey, "PublicKey is empty")
}

// TestSign tests the Sign gRPC endpoint.

func (suite *TestSuite) TestSign() {
	ctx := context.Background()
	message := []byte("avalanche validator message")

	resp, err := suite.proxyPvd.Sign(ctx, &pb.SignRequest{Message: message})
	suite.Require().NoError(err, "Sign endpoint failed")
	suite.Require().NotNil(resp, "Sign response is nil")
	suite.Require().NotEmpty(resp.Signature, "signature is empty")

	ok, err := enclaveCrypto.VerifySignedMessage(crypto.AlgorithmEd25519, resp.Signature, message, suite.publicKey)
	suite.Require().NoError(err, "failed to verify signature")
	suite.Require().True(ok, "signature verification failed")
}

// TestErrorHandling tests that endpoints handle errors correctly.

func (suite *TestSuite) TestErrorHandling() {
	ctx := context.Background()

	tests := []struct {
		name string
		req  *pb.SignRequest
	}{
		{"empty message", &pb.SignRequest{Message: []byte{}}},
		{"nil request", nil},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			_, err := suite.proxyPvd.Sign(ctx, tt.req)
			suite.Require().Error(err, "Sign %s: expected an error but got nil", tt.name)
			st, ok := status.FromError(err)
			suite.Require().True(ok, "Sign %s: error was not a gRPC status error", tt.name)
			suite.Require().Equal(codes.InvalidArgument, st.Code(), "Sign %s: expected code %s, but got %s", tt.name, codes.InvalidArgument, st.Code())
			suite.Require().NotEmpty(st.Message(), "Sign %s: expected a non-empty error message", tt.name)
		})
	}
}

// TestSmokeTests is the main entrypoint for running all smoke tests using testify/suite.

func TestSmokeTests(t *testing.T) {
	suite.Run(t, new(TestSuite))
}
