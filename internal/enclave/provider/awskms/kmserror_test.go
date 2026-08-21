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
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestStatusFromError(t *testing.T) {
	tests := map[string]struct {
		err        error
		wantCode   codes.Code
		wantMapped bool // true => StatusFromError returns a status.Error; false => returns input unchanged
	}{
		"Nil": {
			err: nil, wantMapped: false,
		},
		"AccessDenied": {
			err:        &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "no kms:GenerateDataKey"},
			wantCode:   codes.PermissionDenied,
			wantMapped: true,
		},
		"Throttling": {
			err:        &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"},
			wantCode:   codes.Unavailable,
			wantMapped: true,
		},
		"RequestLimitExceeded": {
			err:        &smithy.GenericAPIError{Code: "RequestLimitExceeded", Message: "Too many"},
			wantCode:   codes.Unavailable,
			wantMapped: true,
		},
		"InvalidCiphertext": {
			err:        &types.InvalidCiphertextException{Message: stringPtr("bad blob")},
			wantCode:   codes.InvalidArgument,
			wantMapped: true,
		},
		"LimitExceeded": {
			err:        &types.LimitExceededException{Message: stringPtr("limit")},
			wantCode:   codes.Unavailable,
			wantMapped: true,
		},
		"WrappedNetError": {
			err:        &url.Error{Op: "Post", URL: "http://127.0.0.1:9000", Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}},
			wantCode:   codes.Unavailable,
			wantMapped: true,
		},
		"Unrecognised": {
			err:        errors.New("something else"),
			wantMapped: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := StatusFromError(tt.err)
			if !tt.wantMapped {
				require.Equal(t, tt.err, got, "unrecognised error must pass through unchanged")
				return
			}
			require.NotNil(t, got)
			st, ok := status.FromError(got)
			require.True(t, ok, "mapped error must be a gRPC status")
			require.Equal(t, tt.wantCode, st.Code())
		})
	}
}

func stringPtr(s string) *string { return &s }
