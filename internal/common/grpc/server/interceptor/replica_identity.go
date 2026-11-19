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

package interceptor

import (
	"context"

	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/internal/common/replica"
	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const invalidReplicaName = "invalid replica name"

type certificateNameStatus string

const (
	certificateNameMatch     certificateNameStatus = "match"
	certificateNameMissing   certificateNameStatus = "missing"
	certificateNameAmbiguous certificateNameStatus = "ambiguous"
	certificateNameMismatch  certificateNameStatus = "mismatch"
)

var replicaIdentityLogger = logging.Get("common.grpc.replica_identity")

// WithReplicaIdentity adds the caller-provided replica ID to the context for the target method.
func WithReplicaIdentity(method string, checkCertificate bool) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if info.FullMethod != method {
			return handler(ctx, req)
		}

		signRequest, ok := req.(*signerv2.SignRequest)
		if !ok {
			return nil, status.Error(codes.InvalidArgument, invalidReplicaName)
		}
		id, err := replica.NewID(signRequest.GetReplicaName())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, invalidReplicaName)
		}

		if checkCertificate {
			nameStatus := certificateNameStatusFromPeer(ctx, id.String())
			if nameStatus != certificateNameMatch {
				replicaIdentityLogger.Warn(ctx, "The client certificate does not support the replica name.", logging.Entries{
					"replica_name":            id.String(),
					"certificate_name_status": nameStatus,
				})
			}
		}

		return handler(replica.NewContext(ctx, id), req)
	}
}

func certificateNameStatusFromPeer(ctx context.Context, replicaName string) certificateNameStatus {
	client, ok := peer.FromContext(ctx)
	if !ok {
		return certificateNameMissing
	}
	tlsInfo, ok := client.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return certificateNameMissing
	}

	leaf := tlsInfo.State.VerifiedChains[0][0]
	if leaf == nil || len(leaf.URIs) == 0 {
		return certificateNameMissing
	}
	if len(leaf.URIs) != 1 {
		return certificateNameAmbiguous
	}
	uri := leaf.URIs[0]
	if uri == nil || !uri.IsAbs() || (uri.Host == "" && uri.Opaque == "" && uri.Path == "") {
		return certificateNameMissing
	}
	if uri.String() != replicaName {
		return certificateNameMismatch
	}
	return certificateNameMatch
}
