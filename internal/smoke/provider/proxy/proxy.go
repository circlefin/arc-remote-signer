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

// Package proxy contains the proxy client for smoke testing.
package proxy

import (
	"context"
	"fmt"
	"log"
	"time"

	pb "github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const defaultSvcAddr = "localhost:10340"

// Provider wraps the gRPC client for smoke testing.
type Provider struct {
	clientV1 pb.SignerServiceClient
	clientV2 signerv2.SignerServiceClient
	conn     *grpc.ClientConn
}

// New creates a new proxy provider.
func New() (*Provider, error) {
	client := &Provider{}

	if err := client.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to service: %w", err)
	}

	return client, nil
}

// connect establishes a gRPC connection to the service with retries.
func (c *Provider) connect() error {
	ctx := context.Background()
	log.Printf("Connecting to signer service at %s", defaultSvcAddr)

	maxRetries := 10
	retryInterval := time.Second
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)

		//nolint:staticcheck // grpc.DialContext deprecation planned for post v1.x
		conn, err := grpc.DialContext(
			ctxTimeout,
			defaultSvcAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		cancel()

		if err != nil {
			lastErr = err
			log.Printf("Failed to connect to signer service (attempt %d/%d): %v", i+1, maxRetries, err)
			time.Sleep(retryInterval)
			continue
		}

		c.conn = conn
		c.clientV1 = pb.NewSignerServiceClient(conn)
		c.clientV2 = signerv2.NewSignerServiceClient(conn)
		return nil
	}
	return fmt.Errorf("failed to connect after %d attempts: %w", maxRetries, lastErr)
}

// PublicKey returns the public key of the signer service.
func (c *Provider) PublicKey(ctx context.Context) (*pb.PublicKeyResponse, error) {
	resp, err := c.clientV1.PublicKey(ctx, &pb.PublicKeyRequest{})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// PublicKeyV2 returns the public key through the version 2 service.
func (c *Provider) PublicKeyV2(ctx context.Context) (*signerv2.PublicKeyResponse, error) {
	return c.clientV2.PublicKey(ctx, &signerv2.PublicKeyRequest{})
}

// Sign signs a message with the signer service.
func (c *Provider) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	resp, err := c.clientV1.Sign(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// SignV2 signs a version 2 request with the signer service.
func (c *Provider) SignV2(
	ctx context.Context,
	req *signerv2.SignRequest,
) (*signerv2.SignResponse, error) {
	resp, err := c.clientV2.Sign(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Close closes the gRPC connection.
func (c *Provider) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
