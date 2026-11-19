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

package signing

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
	"github.com/stretchr/testify/require"
)

func TestValidateMessage_Delegation(t *testing.T) {
	message, err := hex.DecodeString("6172632f617574682f763100096172632d626f6f737400000000000013b22f28fbe8ca981311bfea7ddca2d4264b28d35986d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0000019a08a4a8000000000000bc614eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	require.NoError(t, err)
	metadata := &signerv2.SigningMetadata{Kind: signerv2.MessageKind_MESSAGE_KIND_DELEGATION}
	mutate := func(index int, value byte) []byte {
		result := bytes.Clone(message)
		result[index] = value
		return result
	}
	tests := map[string]struct {
		message []byte
		wantErr bool
	}{
		"canonical preimage":  {message: message},
		"empty preimage":      {wantErr: true},
		"short preimage":      {message: message[:len(message)-1], wantErr: true},
		"long preimage":       {message: append(bytes.Clone(message), 0), wantErr: true},
		"wrong prefix":        {message: mutate(0, 'x'), wantErr: true},
		"wrong version":       {message: mutate(10, '2'), wantErr: true},
		"missing null":        {message: mutate(11, 'x'), wantErr: true},
		"short domain length": {message: mutate(12, 8), wantErr: true},
		"long domain length":  {message: mutate(12, 10), wantErr: true},
		"wrong domain":        {message: mutate(13, 'x'), wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateMessage(metadata, tt.message)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateMessage(t *testing.T) {
	telemetry := &signerv2.SigningMetadata{Kind: signerv2.MessageKind_MESSAGE_KIND_TELEMETRY}
	tests := map[string]struct {
		metadata *signerv2.SigningMetadata
		message  []byte
		wantErr  bool
	}{
		"valid telemetry envelope": {
			metadata: telemetry,
			message:  append([]byte("arc/telemetry/v1\x00"), make([]byte, 32)...),
		},
		"short telemetry digest": {
			metadata: telemetry,
			message:  append([]byte("arc/telemetry/v1\x00"), make([]byte, 31)...),
			wantErr:  true,
		},
		"wrong telemetry domain": {
			metadata: telemetry,
			message:  append([]byte("arc/telemetry/v2\x00"), make([]byte, 32)...),
			wantErr:  true,
		},
		"non-telemetry message": {
			metadata: &signerv2.SigningMetadata{Kind: signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF},
			message:  []byte("validator-proof"),
		},
		"legacy message": {
			message: []byte("legacy"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateMessage(tt.metadata, tt.message)
			if tt.wantErr {
				require.ErrorIs(t, err, errInvalidTelemetryMessage)
				return
			}
			require.NoError(t, err)
		})
	}
}
