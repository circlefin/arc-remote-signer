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

package app

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// initRetryAttempts is the maximum number of Initialize attempts.
const initRetryAttempts = 3

// initRetryBackoff is the fixed delay between Initialize attempts. Tests can
// change this package variable.
var initRetryBackoff = 1 * time.Second

type enclaveKeySource struct {
	existingKey *pb.SecretEnvelope
	generateNew pb.Algorithm
}

// initializeEnclave gets temporary AWS credentials. It calls Initialize with
// one key source. It retries transient failures up to initRetryAttempts times.
// The caller reports non-retryable failures.
//
// This function does not retain the credentials or request. Go does not
// provide a standard way to clear string data from memory.
func initializeEnclave(
	ctx context.Context,
	enclavePvd pb.EnclaveServiceClient,
	awsCfg aws.Config,
	kmsKeyArns []string,
	kmsLocalstackEnabled bool,
	keySource enclaveKeySource,
	logger *logging.Logger,
) (*pb.InitializeResponse, error) {
	if len(kmsKeyArns) == 0 {
		return nil, fmt.Errorf("kmsKeyArns must not be empty")
	}
	if (keySource.existingKey == nil) == (keySource.generateNew == pb.Algorithm_ALGORITHM_UNSPECIFIED) {
		return nil, fmt.Errorf("exactly one enclave key source is required")
	}

	var lastErr error
	invalidateCredentials := false
	for attempt := 1; attempt <= initRetryAttempts; attempt++ {
		if invalidateCredentials {
			if cache, ok := awsCfg.Credentials.(interface{ Invalidate() }); ok {
				cache.Invalidate()
			}
		}
		creds, err := awsCfg.Credentials.Retrieve(ctx)
		if err != nil {
			return nil, fmt.Errorf("retrieve aws credentials: %w", err)
		}

		req := &pb.InitializeRequest{
			Credentials: &pb.AwsCredentials{
				AccessKeyId:     creds.AccessKeyID,
				SecretAccessKey: creds.SecretAccessKey,
				SessionToken:    creds.SessionToken,
				Region:          awsCfg.Region,
			},
			KmsKeyArns:           kmsKeyArns,
			KmsLocalstackEnabled: kmsLocalstackEnabled,
		}
		if keySource.existingKey != nil {
			req.KeySource = &pb.InitializeRequest_ExistingKey{ExistingKey: keySource.existingKey}
		} else {
			req.KeySource = &pb.InitializeRequest_GenerateNew{GenerateNew: keySource.generateNew}
		}

		resp, err := enclavePvd.Initialize(ctx, req)
		if err == nil {
			logger.Info(ctx, "enclave Initialize succeeded", logging.Entries{"attempt": attempt})
			return resp, nil
		}

		code := status.Code(err)
		switch code {
		case codes.Unauthenticated, codes.Unavailable, codes.DeadlineExceeded:
			// An Unauthenticated response causes a retry because the next
			// attempt refreshes cached credentials.
			// DeadlineExceeded is retryable because enclave cold start can
			// exceed a single Initialize RPC deadline; subsequent attempts
			// hit a warm enclave.
			lastErr = err
			invalidateCredentials = code == codes.Unauthenticated
			if attempt < initRetryAttempts {
				logger.Info(ctx, "enclave Initialize returned retryable error, will retry", logging.Entries{
					"attempt": attempt,
					"code":    code.String(),
					"error":   err.Error(),
				})
			}
		case codes.PermissionDenied, codes.InvalidArgument, codes.FailedPrecondition:
			return nil, fmt.Errorf("enclave Initialize rejected request (code=%s, non-retryable): %w", code, err)
		default:
			return nil, fmt.Errorf("enclave Initialize failed (code=%s): %w", code, err)
		}

		if attempt < initRetryAttempts {
			// Use a context-aware delay so cancellation or the total startup
			// deadline stops the retry backoff.
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("enclave Initialize aborted during retry backoff: %w", ctx.Err())
			case <-time.After(initRetryBackoff):
			}
		}
	}

	return nil, fmt.Errorf("enclave Initialize exhausted %d retry attempts: %w", initRetryAttempts, lastErr)
}
