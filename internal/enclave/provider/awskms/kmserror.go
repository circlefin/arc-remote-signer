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

// StatusFromError translates AWS KMS SDK errors to gRPC status codes
// per the CCHAIN-2027 design. Returns nil if err is nil. Returns the
// original err unchanged when the error is not recognised, so the
// caller can apply its own fallback (e.g. wrap as Internal). The name
// mirrors grpc/status.FromError, this being a KMS-aware variant.
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
