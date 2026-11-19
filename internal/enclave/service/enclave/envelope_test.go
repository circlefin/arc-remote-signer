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
	"testing"

	"buf.build/go/protovalidate"
	"github.com/aws/smithy-go"
	"github.com/circlefin/arc-remote-signer/internal/common/crypto/aes"
	"github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	enclavePvd "github.com/circlefin/arc-remote-signer/internal/enclave/provider/enclave"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newEd25519Envelope builds a real Ed25519 key AES-GCM-wrapped under dataKey
// and returns the SecretEnvelope plus the underlying key (so callers can assert
// against its public key). KmsEncryptedDataKey is a placeholder — the fake KMS
// provider decides what plaintext it maps to.
func newEd25519Envelope(t *testing.T, dataKey []byte) (*pb.SecretEnvelope, crypto.Key) {
	t.Helper()
	sk, err := crypto.NewSecretKey(crypto.AlgorithmEd25519)
	require.NoError(t, err)
	skBytes, err := sk.Serialize()
	require.NoError(t, err)
	cipher, nonce, err := aes.EncryptGCM(dataKey, skBytes)
	require.NoError(t, err)
	return &pb.SecretEnvelope{
		Algorithm:           pb.Algorithm_ALGORITHM_ED25519,
		KmsEncryptedDataKey: []byte("kms-ciphertext"),
		EncryptedPrivateKey: cipher,
		Nonce:               nonce,
	}, sk
}

func newReadyService(
	key crypto.Key,
	nitro bool,
	enclaveProvider enclavePvd.Provider,
) *Service {
	gate := newInitGate(nil)
	gate.ready.Store(&readyState{key: key, response: &pb.InitializeResponse{PublicKey: []byte("ready")}})
	return &Service{
		nitroEnclaveEnabled: nitro,
		enclavePvd:          enclaveProvider,
		gate:                gate,
	}
}

func TestDecryptDataKey(t *testing.T) {
	t.Run("dev returns plaintext data key", func(t *testing.T) {
		dataKey := bytes.Repeat([]byte{0x2a}, 32)
		s := &Service{nitroEnclaveEnabled: false}
		pvd := &fakeKmsProvider{
			decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) {
				return dataKey, nil, nil // dev: KMS returns plaintext data key
			},
		}

		got, err := s.decryptDataKey(context.Background(), pvd, []byte("kms-ct"))
		require.NoError(t, err)
		require.Equal(t, dataKey, got)
	})

	t.Run("nitro decrypts CiphertextForRecipient with the enclave RSA key", func(t *testing.T) {
		dataKey := bytes.Repeat([]byte{0x3b}, 32)
		recipientCt := []byte("recipient-ciphertext")
		ctrl := gomock.NewController(t)
		enclaveProvider := enclavePvd.NewMockProvider(ctrl)
		enclaveProvider.EXPECT().DecryptKMSEnvelopedKey(recipientCt).Return(dataKey, nil)

		s := &Service{nitroEnclaveEnabled: true, enclavePvd: enclaveProvider}
		pvd := &fakeKmsProvider{
			decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) {
				return nil, recipientCt, nil // nitro: KMS returns CiphertextForRecipient
			},
		}

		got, err := s.decryptDataKey(context.Background(), pvd, []byte("kms-ct"))
		require.NoError(t, err)
		require.Equal(t, dataKey, got)
	})

	t.Run("nitro recipient decryption failure returns an opaque recovery error", func(t *testing.T) {
		recipientCt := []byte("recipient-ciphertext")
		ctrl := gomock.NewController(t)
		enclaveProvider := enclavePvd.NewMockProvider(ctrl)
		enclaveProvider.EXPECT().
			DecryptKMSEnvelopedKey(recipientCt).
			Return(nil, errors.New("rsa decrypt failed"))

		s := &Service{nitroEnclaveEnabled: true, enclavePvd: enclaveProvider}
		pvd := &fakeKmsProvider{
			decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) {
				return nil, recipientCt, nil
			},
		}

		_, err := s.decryptDataKey(context.Background(), pvd, []byte("kms-ct"))
		require.Equal(t, codes.Internal, status.Code(err))
		require.Equal(t, "key recovery failed", status.Convert(err).Message())
		require.NotContains(t, err.Error(), "rsa decrypt failed")
	})

	t.Run("errors when kms provider not initialized", func(t *testing.T) {
		s := &Service{}
		_, err := s.decryptDataKey(context.Background(), nil, []byte("kms-ct"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "kms provider not initialized")
	})
}

func TestGenerateEnvelopeCandidateAddsContextToKMSError(t *testing.T) {
	kmsErr := &smithy.GenericAPIError{
		Code:    "ThrottlingException",
		Message: "request throttled",
	}
	pvd := &fakeKmsProvider{
		generateDataKey: func(context.Context) ([]byte, []byte, []byte, error) {
			return nil, nil, nil, kmsErr
		},
	}

	envelope, key, publicKey, err := (&Service{}).generateEnvelopeCandidate(
		context.Background(),
		pvd,
		pb.Algorithm_ALGORITHM_ED25519,
	)

	require.Nil(t, envelope)
	require.Nil(t, key)
	require.Nil(t, publicKey)
	require.ErrorIs(t, err, kmsErr)
	require.Contains(t, err.Error(), "kms generate data key")
}

func TestGenerateEnvelopeCollapsesPostKMSFailures(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T) (*Service, *fakeKmsProvider)
	}{
		{
			name: "KMS recipient decryption",
			setup: func(t *testing.T) (*Service, *fakeKmsProvider) {
				recipientCt := []byte("recipient-ciphertext")
				enclaveProvider := enclavePvd.NewMockProvider(gomock.NewController(t))
				enclaveProvider.EXPECT().
					DecryptKMSEnvelopedKey(recipientCt).
					Return(nil, errors.New("recipient parser detail"))
				return &Service{
						nitroEnclaveEnabled: true,
						enclavePvd:          enclaveProvider,
					}, &fakeKmsProvider{
						generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
							return nil, []byte("kms-ciphertext"), recipientCt, nil
						},
					}
			},
		},
		{
			name: "data key deserialization",
			setup: func(_ *testing.T) (*Service, *fakeKmsProvider) {
				return &Service{}, &fakeKmsProvider{
					generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
						return []byte("invalid data key length"), []byte("kms-ciphertext"), nil, nil
					},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, pvd := tt.setup(t)
			_, _, _, err := s.generateEnvelopeCandidate(
				context.Background(),
				pvd,
				pb.Algorithm_ALGORITHM_ED25519,
			)
			got := status.Convert(err)
			require.Equal(t, codes.Internal, got.Code())
			require.Equal(t, "key generation failed", got.Message())
		})
	}
}

func TestGenerateEnvelope_ReturnsSecretEnvelope_Dev(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x11}, 32)
	s := &Service{nitroEnclaveEnabled: false}
	pvd := &fakeKmsProvider{
		generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
			return dataKey, []byte("kms-cipher-blob"), nil, nil // dev: plaintext data key
		},
	}

	env, secretKey, publicKey, err := s.generateEnvelopeCandidate(
		context.Background(),
		pvd,
		pb.Algorithm_ALGORITHM_ED25519,
	)
	require.NoError(t, err)
	require.NotNil(t, env)
	require.NotNil(t, secretKey)
	require.Equal(t, []byte("kms-cipher-blob"), env.KmsEncryptedDataKey)
	require.Equal(t, pb.Algorithm_ALGORITHM_ED25519, env.Algorithm)
	require.NotEmpty(t, publicKey)
	require.NotEmpty(t, env.EncryptedPrivateKey)
	require.NotEmpty(t, env.Nonce)
}

func TestGenerateEnvelope_ReturnsSecretEnvelope_Nitro(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x22}, 32)
	recipientCt := []byte("recipient-ciphertext")
	ctrl := gomock.NewController(t)
	enclaveProvider := enclavePvd.NewMockProvider(ctrl)
	enclaveProvider.EXPECT().DecryptKMSEnvelopedKey(recipientCt).Return(dataKey, nil)

	s := &Service{nitroEnclaveEnabled: true, enclavePvd: enclaveProvider}
	pvd := &fakeKmsProvider{
		generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
			return nil, []byte("kms-cipher-blob"), recipientCt, nil // nitro: KMS omits plaintext
		},
	}

	env, secretKey, _, err := s.generateEnvelopeCandidate(
		context.Background(),
		pvd,
		pb.Algorithm_ALGORITHM_ED25519,
	)
	require.NoError(t, err)
	require.NotNil(t, env)
	require.NotNil(t, secretKey)
	require.Equal(t, []byte("kms-cipher-blob"), env.KmsEncryptedDataKey)
}

func TestGenerateEnvelope_NitroRecipientDecryptionFailureReturnsOpaqueError(t *testing.T) {
	recipientCt := []byte("recipient-ciphertext")
	ctrl := gomock.NewController(t)
	enclaveProvider := enclavePvd.NewMockProvider(ctrl)
	enclaveProvider.EXPECT().
		DecryptKMSEnvelopedKey(recipientCt).
		Return(nil, errors.New("rsa decrypt failed"))

	s := &Service{
		nitroEnclaveEnabled: true,
		enclavePvd:          enclaveProvider,
	}
	pvd := &fakeKmsProvider{
		generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
			return nil, []byte("kms-cipher-blob"), recipientCt, nil
		},
	}

	_, _, _, err := s.generateEnvelopeCandidate(
		context.Background(),
		pvd,
		pb.Algorithm_ALGORITHM_ED25519,
	)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Equal(t, "key generation failed", status.Convert(err).Message())
	require.NotContains(t, err.Error(), "rsa decrypt failed")
}

func TestGetPublicKey_AttestsDerivedKey_Nitro(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x2a}, 32)
	_, secretKey := newEd25519Envelope(t, dataKey)
	wantPublicKey, err := secretKey.PublicKey()
	require.NoError(t, err)
	wantDocument := []byte("attestation-document")

	ctrl := gomock.NewController(t)
	enclaveProvider := enclavePvd.NewMockProvider(ctrl)
	enclaveProvider.EXPECT().
		Attest(wantPublicKey).
		Return(wantDocument, nil)
	s := newReadyService(secretKey, true, enclaveProvider)

	resp, err := s.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{})

	require.NoError(t, err)
	require.Equal(t, wantPublicKey, resp.PublicKey)
	require.Equal(t, wantDocument, resp.AttestationDocument)
}

func TestGetPublicKey_FailsClosedWhenAttestationFails_Nitro(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x2a}, 32)
	_, secretKey := newEd25519Envelope(t, dataKey)
	wantPublicKey, err := secretKey.PublicKey()
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	enclaveProvider := enclavePvd.NewMockProvider(ctrl)
	enclaveProvider.EXPECT().
		Attest(wantPublicKey).
		Return(nil, errors.New("NSM failure detail"))
	s := newReadyService(secretKey, true, enclaveProvider)

	resp, err := s.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{})

	require.Nil(t, resp)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Contains(t, err.Error(), "failed to attest public key")
	require.NotContains(t, err.Error(), "NSM failure detail")
}

func TestGetPublicKey_FailsWhenEnclaveProviderIsNil_Nitro(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x2a}, 32)
	_, secretKey := newEd25519Envelope(t, dataKey)

	s := newReadyService(secretKey, true, nil)

	resp, err := s.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{})

	require.Nil(t, resp)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Contains(t, err.Error(), "enclave provider is nil while nitro enclave is enabled")
}

// TestNitroNilEnclaveProvider verifies that envelope operations require an
// enclave provider in Nitro mode.
func TestNitroNilEnclaveProvider(t *testing.T) {
	t.Run("generate envelope candidate", func(t *testing.T) {
		s := &Service{nitroEnclaveEnabled: true}
		pvd := &fakeKmsProvider{
			generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
				return nil, []byte("kms-cipher-blob"), []byte("recipient-ct"), nil
			},
		}
		_, _, _, err := s.generateEnvelopeCandidate(
			context.Background(),
			pvd,
			pb.Algorithm_ALGORITHM_ED25519,
		)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		require.Contains(t, err.Error(), "enclave provider is nil")
	})
	t.Run("decrypt data key", func(t *testing.T) {
		s := &Service{nitroEnclaveEnabled: true}
		pvd := &fakeKmsProvider{
			decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) {
				return nil, []byte("recipient-ct"), nil
			},
		}
		_, err := s.decryptDataKey(context.Background(), pvd, []byte("kms-ct"))
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		require.Contains(t, err.Error(), "enclave provider is nil")
	})
}

func TestReadyStateRequestsDoNotRequireSecretEnvelope(t *testing.T) {
	v, err := protovalidate.New()
	require.NoError(t, err)

	t.Run("GetPublicKey", func(t *testing.T) {
		require.NoError(t, v.Validate(&pb.GetPublicKeyRequest{}))
	})
	t.Run("SignMessage", func(t *testing.T) {
		msg := []byte("m")
		require.NoError(t, v.Validate(&pb.SignMessageRequest{Message: msg}))
	})
}
