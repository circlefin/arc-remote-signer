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

// initRetryAttempts is the number of times the host retries
// Initialize on retryable errors (Unavailable, DeadlineExceeded)
// before giving up.
const initRetryAttempts = 3

// initRetryBackoff is the fixed delay between Initialize retry attempts.
// Overridable via package-private var for tests so the retry table does
// not block test runs for several seconds.
var initRetryBackoff = 1 * time.Second

// initializeEnclave drives the host-side enclave-init flow: retrieve
// temporary AWS credentials from the SDK's default chain (IMDSv2 in
// production, static placeholder in dev/LocalStack), forward them to
// the enclave via the Initialize RPC, and retry transient failures up
// to initRetryAttempts times. Non-retryable failures (PermissionDenied,
// InvalidArgument, ...) panic the process so the orchestrator can
// restart with corrected configuration.
//
// Credentials and the request struct live only inside this function's
// stack frame and are not retained by the Service. Strings are
// proto-generated and cannot be explicitly zeroed; we rely on the
// frame going out of scope plus the runtime eventually reusing the
// memory.
func initializeEnclave(
	ctx context.Context,
	enclavePvd pb.EnclaveServiceClient,
	awsCfg aws.Config,
	kmsKeyArns []string,
	kmsLocalstackEnabled bool,
	logger *logging.Logger,
) error {
	if len(kmsKeyArns) == 0 {
		return fmt.Errorf("kmsKeyArns must not be empty")
	}

	creds, err := awsCfg.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("retrieve aws credentials: %w", err)
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

	var lastErr error
	for attempt := 1; attempt <= initRetryAttempts; attempt++ {
		_, err := enclavePvd.Initialize(ctx, req)
		if err == nil {
			logger.Info(ctx, "enclave Initialize succeeded", logging.Entries{"attempt": attempt})
			return nil
		}

		code := status.Code(err)
		switch code {
		case codes.Unavailable, codes.DeadlineExceeded:
			// DeadlineExceeded is retryable because enclave cold start can
			// exceed a single Initialize RPC deadline; subsequent attempts
			// hit a warm enclave.
			lastErr = err
			if attempt < initRetryAttempts {
				logger.Info(ctx, "enclave Initialize returned retryable error, will retry", logging.Entries{
					"attempt": attempt,
					"code":    code.String(),
					"error":   err.Error(),
				})
			}
		case codes.PermissionDenied, codes.InvalidArgument, codes.Unauthenticated, codes.FailedPrecondition:
			return fmt.Errorf("enclave Initialize rejected request (code=%s, non-retryable): %w", code, err)
		default:
			return fmt.Errorf("enclave Initialize failed (code=%s): %w", code, err)
		}

		if attempt < initRetryAttempts {
			// ctx-aware sleep so SIGTERM during init doesn't stall up to
			// initRetryBackoff * (initRetryAttempts-1) seconds. In
			// production app.Run passes context.Background() here, so this
			// cancel branch is exercised primarily by tests; it remains
			// wired so a future caller can plumb a cancellable ctx without
			// changing this function.
			select {
			case <-ctx.Done():
				return fmt.Errorf("enclave Initialize aborted during retry backoff: %w", ctx.Err())
			case <-time.After(initRetryBackoff):
			}
		}
	}

	return fmt.Errorf("enclave Initialize exhausted %d retry attempts: %w", initRetryAttempts, lastErr)
}
