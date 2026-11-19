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

package awskms

import (
	"errors"
	"net"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// StatusFromError converts AWS KMS SDK errors to gRPC status codes.
// It returns nil when err is nil.
// If it does not recognize the error, it returns the same error.
// The caller can then apply a fallback, such as an Internal status.
// The function name follows grpc/status.FromError.
func StatusFromError(err error) error {
	if err == nil {
		return nil
	}

	var invalidCt *types.InvalidCiphertextException
	if errors.As(err, &invalidCt) {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	var limitExc *types.LimitExceededException
	if errors.As(err, &limitExc) {
		return status.Error(codes.Unavailable, err.Error())
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDeniedException":
			return status.Error(codes.PermissionDenied, err.Error())
		case "ExpiredTokenException", "InvalidClientTokenId", "UnrecognizedClientException":
			return status.Error(codes.Unauthenticated, err.Error())
		case "ThrottlingException", "RequestLimitExceeded":
			return status.Error(codes.Unavailable, err.Error())
		}
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return status.Error(codes.Unavailable, err.Error())
	}

	return err
}

// credentialAuthError returns err when it is a credential-wide KMS
// authentication failure. These errors are not region-specific, so a later
// regional transport or timeout failure must not hide them.
func credentialAuthError(err error) error {
	mapped := StatusFromError(err)
	if mapped != err && status.Code(mapped) == codes.Unauthenticated {
		return err
	}
	return nil
}
