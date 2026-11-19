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

package proto

import (
	"testing"

	"buf.build/go/protovalidate"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestSignMessageRequest_MetadataContract(t *testing.T) {
	fields := (&pb.SignMessageRequest{}).ProtoReflect().Descriptor().Fields()
	metadata := fields.ByName("metadata")

	require.NotNil(t, metadata)
	require.Equal(t, protoreflect.FieldNumber(5), metadata.Number())
	require.Equal(t, protoreflect.FullName("arc.signer.v2.SigningMetadata"), metadata.Message().FullName())
}

func TestSignMessageRequest_MetadataValidation(t *testing.T) {
	validator, err := protovalidate.New()
	require.NoError(t, err)

	tests := map[string]struct {
		metadata *signerv2.SigningMetadata
		wantErr  bool
	}{
		"valid metadata": {
			metadata: &signerv2.SigningMetadata{
				Kind:   signerv2.MessageKind_MESSAGE_KIND_PREVOTE,
				Height: proto.Uint64(1),
				Round:  proto.Uint64(0),
			},
		},
		"missing height": {
			metadata: &signerv2.SigningMetadata{
				Kind:  signerv2.MessageKind_MESSAGE_KIND_PREVOTE,
				Round: proto.Uint64(0),
			},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			req := &pb.SignMessageRequest{
				Message:  []byte("message"),
				Metadata: tt.metadata,
			}
			err := validator.Validate(req)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
