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

package enclave

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/common/crypto/aes"
	"github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	enclavePvd "github.com/circlefin/arc-remote-signer/internal/enclave/provider/enclave"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newEd25519Envelope(t *testing.T, dataKey []byte) (*pb.SecretEnvelope, crypto.Key) {
	t.Helper()
	key, err := crypto.NewSecretKey(crypto.AlgorithmEd25519)
	require.NoError(t, err)
	keyBytes, err := key.Serialize()
	require.NoError(t, err)
	ciphertext, nonce, err := aes.EncryptGCM(dataKey, keyBytes)
	require.NoError(t, err)
	return &pb.SecretEnvelope{
		Algorithm:           pb.Algorithm_ALGORITHM_ED25519,
		KmsEncryptedDataKey: []byte("kms-ciphertext"),
		EncryptedPrivateKey: ciphertext,
		Nonce:               nonce,
	}, key
}

func TestFingerprintKeySource(t *testing.T) {
	generate := generateInitRequest()
	same := generateInitRequest()
	different := generateInitRequest()
	different.KeySource = &pb.InitializeRequest_GenerateNew{GenerateNew: pb.Algorithm_ALGORITHM_BLS}

	first, err := fingerprintKeySource(generate)
	require.NoError(t, err)
	second, err := fingerprintKeySource(same)
	require.NoError(t, err)
	other, err := fingerprintKeySource(different)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.NotEqual(t, first, other)
}

func TestLoadKeyCandidate_RecoversWrappedKey(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x22}, 32)
	envelope, wantKey := newEd25519Envelope(t, dataKey)
	wantPublicKey, err := wantKey.PublicKey()
	require.NoError(t, err)
	pvd := &fakeKmsProvider{
		decrypt: func(_ context.Context, ciphertext []byte) ([]byte, []byte, error) {
			require.Equal(t, envelope.KmsEncryptedDataKey, ciphertext)
			return dataKey, nil, nil
		},
	}

	gotKey, err := (&Service{}).loadKeyCandidate(context.Background(), pvd, envelope)

	require.NoError(t, err)
	gotPublicKey, err := gotKey.PublicKey()
	require.NoError(t, err)
	require.Equal(t, wantPublicKey, gotPublicKey)
}

func TestGenerateEnvelopeCandidate_NitroDecryptsRecipient(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x33}, 32)
	recipientCiphertext := []byte("recipient-ciphertext")
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			return nil, []byte("kms-ciphertext"), recipientCiphertext, nil
		},
	}
	ctrl := gomock.NewController(t)
	enclaveProvider := enclavePvd.NewMockProvider(ctrl)
	enclaveProvider.EXPECT().DecryptKMSEnvelopedKey(recipientCiphertext).Return(dataKey, nil)
	svc := &Service{nitroEnclaveEnabled: true, enclavePvd: enclaveProvider}

	envelope, key, publicKey, err := svc.generateEnvelopeCandidate(
		context.Background(),
		pvd,
		pb.Algorithm_ALGORITHM_ED25519,
	)

	require.NoError(t, err)
	require.NotNil(t, key)
	require.NotEmpty(t, publicKey)
	require.Equal(t, []byte("kms-ciphertext"), envelope.GetKmsEncryptedDataKey())
}

func TestKMSStatusError(t *testing.T) {
	tests := map[string]struct {
		err      error
		wantCode codes.Code
	}{
		"canceled": {err: context.Canceled, wantCode: codes.Canceled},
		"deadline": {err: context.DeadlineExceeded, wantCode: codes.DeadlineExceeded},
		"internal": {err: errors.New("boom"), wantCode: codes.Internal},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := kmsStatusError("kms operation", fmt.Errorf("wrapped: %w", tt.err))
			require.Equal(t, tt.wantCode, status.Code(got))
		})
	}
}
