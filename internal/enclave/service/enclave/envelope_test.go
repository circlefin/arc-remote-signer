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
	"net"
	"net/url"
	"testing"

	"buf.build/go/protovalidate"
	"github.com/aws/smithy-go"
	"github.com/circlefin/arc-remote-signer/internal/common/crypto/aes"
	"github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	enclavePvd "github.com/circlefin/arc-remote-signer/internal/enclave/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/keystore"
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

func TestEnvelopeCacheKey(t *testing.T) {
	base := &pb.SecretEnvelope{
		Algorithm:           pb.Algorithm_ALGORITHM_ED25519,
		KmsEncryptedDataKey: []byte("k"),
		EncryptedPrivateKey: []byte("p"),
		Nonce:               []byte("n"),
	}
	same := &pb.SecretEnvelope{
		Algorithm:           pb.Algorithm_ALGORITHM_ED25519,
		KmsEncryptedDataKey: []byte("k"),
		EncryptedPrivateKey: []byte("p"),
		Nonce:               []byte("n"),
	}
	diff := &pb.SecretEnvelope{
		Algorithm:           pb.Algorithm_ALGORITHM_ED25519,
		KmsEncryptedDataKey: []byte("k"),
		EncryptedPrivateKey: []byte("p2"),
		Nonce:               []byte("n"),
	}

	t.Run("same fields yield the same key", func(t *testing.T) {
		require.Equal(t, envelopeCacheKey(base), envelopeCacheKey(same))
	})
	t.Run("different ciphertext yields a different key", func(t *testing.T) {
		require.NotEqual(t, envelopeCacheKey(base), envelopeCacheKey(diff))
	})
}

func TestDecryptDataKeyFromKMS(t *testing.T) {
	t.Run("dev returns plaintext data key", func(t *testing.T) {
		dataKey := bytes.Repeat([]byte{0x2a}, 32)
		s := &Service{nitroEnclaveEnabled: false}
		s.setKMSProvider(&fakeKmsProvider{
			decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) {
				return dataKey, nil, nil // dev: KMS returns plaintext data key
			},
		})

		got, err := s.decryptDataKeyFromKMS(context.Background(), []byte("kms-ct"))
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
		s.setKMSProvider(&fakeKmsProvider{
			decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) {
				return nil, recipientCt, nil // nitro: KMS returns CiphertextForRecipient
			},
		})

		got, err := s.decryptDataKeyFromKMS(context.Background(), []byte("kms-ct"))
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
		s.setKMSProvider(&fakeKmsProvider{
			decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) {
				return nil, recipientCt, nil
			},
		})

		_, err := s.decryptDataKeyFromKMS(context.Background(), []byte("kms-ct"))
		require.Equal(t, codes.Internal, status.Code(err))
		require.Equal(t, "key recovery failed", status.Convert(err).Message())
		require.NotContains(t, err.Error(), "rsa decrypt failed")
	})

	t.Run("errors when kms provider not initialized", func(t *testing.T) {
		s := &Service{}
		_, err := s.decryptDataKeyFromKMS(context.Background(), []byte("kms-ct"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "kms provider not initialized")
	})
}

func TestKMSStatusError(t *testing.T) {
	tests := map[string]struct {
		err      error
		wantCode codes.Code
	}{
		"context canceled maps to Canceled":          {err: context.Canceled, wantCode: codes.Canceled},
		"deadline exceeded maps to DeadlineExceeded": {err: context.DeadlineExceeded, wantCode: codes.DeadlineExceeded},
		"wrapped context canceled maps to Canceled":  {err: fmt.Errorf("kms dial: %w", context.Canceled), wantCode: codes.Canceled},
		"unrecognized error falls back to Internal":  {err: errors.New("boom"), wantCode: codes.Internal},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := kmsStatusError("kms decrypt data key", tt.err)
			require.Equal(t, tt.wantCode, status.Code(err))
		})
	}

	t.Run("prefix is preserved on the Internal fallback", func(t *testing.T) {
		err := kmsStatusError("kms decrypt data key", errors.New("boom"))
		require.Contains(t, err.Error(), "kms decrypt data key")
	})
}

type keyRecoveryFailureFixture struct {
	name  string
	setup func(*testing.T) (*Service, *pb.SecretEnvelope)
}

func keyRecoveryFailureFixtures() []keyRecoveryFailureFixture {
	baseEnvelope := func() *pb.SecretEnvelope {
		return &pb.SecretEnvelope{
			Algorithm:           pb.Algorithm_ALGORITHM_ED25519,
			KmsEncryptedDataKey: []byte("kms-ciphertext"),
			EncryptedPrivateKey: []byte("unused"),
			Nonce:               []byte("unused"),
		}
	}

	return []keyRecoveryFailureFixture{
		{
			name: "KMS recipient decryption",
			setup: func(t *testing.T) (*Service, *pb.SecretEnvelope) {
				recipientCt := []byte("recipient-ciphertext")
				enclaveProvider := enclavePvd.NewMockProvider(gomock.NewController(t))
				enclaveProvider.EXPECT().
					DecryptKMSEnvelopedKey(recipientCt).
					Return(nil, errors.New("recipient parser detail"))
				s := &Service{
					nitroEnclaveEnabled: true,
					keystore:            keystore.New(),
					enclavePvd:          enclaveProvider,
				}
				s.setKMSProvider(&fakeKmsProvider{
					decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) {
						return nil, recipientCt, nil
					},
				})
				return s, baseEnvelope()
			},
		},
		{
			name: "data key deserialization",
			setup: func(_ *testing.T) (*Service, *pb.SecretEnvelope) {
				s := &Service{keystore: keystore.New()}
				s.setKMSProvider(&fakeKmsProvider{
					decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) {
						return []byte("invalid data key length"), nil, nil
					},
				})
				return s, baseEnvelope()
			},
		},
		{
			name: "private key decryption",
			setup: func(_ *testing.T) (*Service, *pb.SecretEnvelope) {
				dataKey := bytes.Repeat([]byte{0x2a}, 32)
				s := &Service{keystore: keystore.New()}
				s.setKMSProvider(&fakeKmsProvider{
					decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) {
						return dataKey, nil, nil
					},
				})
				return s, baseEnvelope()
			},
		},
		{
			name: "private key deserialization",
			setup: func(t *testing.T) (*Service, *pb.SecretEnvelope) {
				dataKey := bytes.Repeat([]byte{0x2a}, 32)
				ciphertext, nonce, err := aes.EncryptGCM(dataKey, []byte("invalid private key length"))
				require.NoError(t, err)
				s := &Service{keystore: keystore.New()}
				s.setKMSProvider(&fakeKmsProvider{
					decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) {
						return dataKey, nil, nil
					},
				})
				env := baseEnvelope()
				env.EncryptedPrivateKey = ciphertext
				env.Nonce = nonce
				return s, env
			},
		},
	}
}

func TestReadRPCsCollapseKeyRecoveryFailures(t *testing.T) {
	rpcs := []struct {
		name string
		call func(context.Context, *Service, *pb.SecretEnvelope) error
	}{
		{
			name: "GetPublicKey",
			call: func(ctx context.Context, s *Service, env *pb.SecretEnvelope) error {
				_, err := s.GetPublicKey(ctx, &pb.GetPublicKeyRequest{SecretEnvelope: env})
				return err
			},
		},
		{
			name: "SignMessage",
			call: func(ctx context.Context, s *Service, env *pb.SecretEnvelope) error {
				_, err := s.SignMessage(ctx, &pb.SignMessageRequest{
					SecretEnvelope: env,
					Message:        []byte("message"),
				})
				return err
			},
		},
	}

	for _, rpc := range rpcs {
		t.Run(rpc.name, func(t *testing.T) {
			for _, fixture := range keyRecoveryFailureFixtures() {
				t.Run(fixture.name, func(t *testing.T) {
					s, env := fixture.setup(t)
					got := status.Convert(rpc.call(context.Background(), s, env))
					require.Equal(t, codes.Internal, got.Code())
					require.Equal(t, "key recovery failed", got.Message())
				})
			}
		})
	}
}

func TestGenerateKeyCollapsesPostKMSFailures(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T) *Service
	}{
		{
			name: "KMS recipient decryption",
			setup: func(t *testing.T) *Service {
				recipientCt := []byte("recipient-ciphertext")
				enclaveProvider := enclavePvd.NewMockProvider(gomock.NewController(t))
				enclaveProvider.EXPECT().
					DecryptKMSEnvelopedKey(recipientCt).
					Return(nil, errors.New("recipient parser detail"))
				s := &Service{
					nitroEnclaveEnabled: true,
					keystore:            keystore.New(),
					enclavePvd:          enclaveProvider,
				}
				s.setKMSProvider(&fakeKmsProvider{
					generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
						return nil, []byte("kms-ciphertext"), recipientCt, nil
					},
				})
				return s
			},
		},
		{
			name: "data key deserialization",
			setup: func(_ *testing.T) *Service {
				s := &Service{keystore: keystore.New()}
				s.setKMSProvider(&fakeKmsProvider{
					generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
						return []byte("invalid data key length"), []byte("kms-ciphertext"), nil, nil
					},
				})
				return s
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.setup(t).GenerateKey(context.Background(), &pb.GenerateKeyRequest{
				Algorithm: pb.Algorithm_ALGORITHM_ED25519,
			})
			got := status.Convert(err)
			require.Equal(t, codes.Internal, got.Code())
			require.Equal(t, "key generation failed", got.Message())
		})
	}
}

func TestKeyRPCsPreserveKMSOperationalErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{
			name: "authorization",
			err: &smithy.GenericAPIError{
				Code:    "AccessDeniedException",
				Message: "policy detail",
			},
			wantCode: codes.PermissionDenied,
		},
		{
			name: "throttling",
			err: &smithy.GenericAPIError{
				Code:    "ThrottlingException",
				Message: "rate detail",
			},
			wantCode: codes.Unavailable,
		},
		{
			name:     "transport",
			err:      &url.Error{Op: "Post", URL: "https://kms.example", Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}},
			wantCode: codes.Unavailable,
		},
		{
			name:     "cancellation",
			err:      context.Canceled,
			wantCode: codes.Canceled,
		},
		{
			name:     "deadline",
			err:      context.DeadlineExceeded,
			wantCode: codes.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{keystore: keystore.New()}
			s.setKMSProvider(&fakeKmsProvider{
				decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) {
					return nil, nil, tt.err
				},
			})

			_, err := s.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{
				SecretEnvelope: &pb.SecretEnvelope{Algorithm: pb.Algorithm_ALGORITHM_ED25519},
			})
			got := status.Convert(err)
			require.Equal(t, tt.wantCode, got.Code())
			if tt.wantCode != codes.Canceled && tt.wantCode != codes.DeadlineExceeded {
				require.Contains(t, got.Message(), "kms decrypt data key")
			}
		})
	}
}

func TestGenerateKey_ReturnsSecretEnvelope_Dev(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x11}, 32)
	ks := keystore.New()
	s := &Service{nitroEnclaveEnabled: false, keystore: ks}
	s.setKMSProvider(&fakeKmsProvider{
		generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
			return dataKey, []byte("kms-cipher-blob"), nil, nil // dev: plaintext data key
		},
	})

	resp, err := s.GenerateKey(context.Background(), &pb.GenerateKeyRequest{Algorithm: pb.Algorithm_ALGORITHM_ED25519})
	require.NoError(t, err)
	require.NotNil(t, resp.SecretEnvelope)
	require.Equal(t, []byte("kms-cipher-blob"), resp.SecretEnvelope.KmsEncryptedDataKey)
	require.Equal(t, pb.Algorithm_ALGORITHM_ED25519, resp.SecretEnvelope.Algorithm)
	require.NotEmpty(t, resp.PublicKey)
	require.NotEmpty(t, resp.SecretEnvelope.EncryptedPrivateKey)
	require.NotEmpty(t, resp.SecretEnvelope.Nonce)
	// Generated key is cached under the envelope key so a later read RPC hits cache.
	require.NotNil(t, ks.Get(envelopeCacheKey(resp.SecretEnvelope)))
}

func TestGenerateKey_ReturnsSecretEnvelope_Nitro(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x22}, 32)
	recipientCt := []byte("recipient-ciphertext")
	ctrl := gomock.NewController(t)
	enclaveProvider := enclavePvd.NewMockProvider(ctrl)
	enclaveProvider.EXPECT().DecryptKMSEnvelopedKey(recipientCt).Return(dataKey, nil)

	ks := keystore.New()
	s := &Service{nitroEnclaveEnabled: true, keystore: ks, enclavePvd: enclaveProvider}
	s.setKMSProvider(&fakeKmsProvider{
		generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
			return nil, []byte("kms-cipher-blob"), recipientCt, nil // nitro: KMS omits plaintext
		},
	})

	resp, err := s.GenerateKey(context.Background(), &pb.GenerateKeyRequest{Algorithm: pb.Algorithm_ALGORITHM_ED25519})
	require.NoError(t, err)
	require.NotNil(t, resp.SecretEnvelope)
	require.Equal(t, []byte("kms-cipher-blob"), resp.SecretEnvelope.KmsEncryptedDataKey)
	require.NotNil(t, ks.Get(envelopeCacheKey(resp.SecretEnvelope)))
}

func TestGenerateKey_NitroRecipientDecryptionFailureReturnsOpaqueError(t *testing.T) {
	recipientCt := []byte("recipient-ciphertext")
	ctrl := gomock.NewController(t)
	enclaveProvider := enclavePvd.NewMockProvider(ctrl)
	enclaveProvider.EXPECT().
		DecryptKMSEnvelopedKey(recipientCt).
		Return(nil, errors.New("rsa decrypt failed"))

	s := &Service{
		nitroEnclaveEnabled: true,
		keystore:            keystore.New(),
		enclavePvd:          enclaveProvider,
	}
	s.setKMSProvider(&fakeKmsProvider{
		generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
			return nil, []byte("kms-cipher-blob"), recipientCt, nil
		},
	})

	_, err := s.GenerateKey(
		context.Background(),
		&pb.GenerateKeyRequest{Algorithm: pb.Algorithm_ALGORITHM_ED25519},
	)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Equal(t, "key generation failed", status.Convert(err).Message())
	require.NotContains(t, err.Error(), "rsa decrypt failed")
}

func TestSignMessage_WithSecretEnvelope_Dev(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x2a}, 32)
	env, _ := newEd25519Envelope(t, dataKey)
	var kmsCalls int
	s := &Service{nitroEnclaveEnabled: false, keystore: keystore.New()}
	s.setKMSProvider(&fakeKmsProvider{
		decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) {
			kmsCalls++
			return dataKey, nil, nil
		},
	})

	resp, err := s.SignMessage(context.Background(), &pb.SignMessageRequest{
		SecretEnvelope: env, Message: []byte("hello"),
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.Signature)

	// Second call must hit the cache: no additional KMS Decrypt.
	_, err = s.SignMessage(context.Background(), &pb.SignMessageRequest{
		SecretEnvelope: env, Message: []byte("hello2"),
	})
	require.NoError(t, err)
	require.Equal(t, 1, kmsCalls, "warm cache must not call KMS again")
}

func TestGetPublicKey_WithSecretEnvelope_Dev(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x2a}, 32)
	env, sk := newEd25519Envelope(t, dataKey)
	wantPub, err := sk.PublicKey()
	require.NoError(t, err)

	s := &Service{nitroEnclaveEnabled: false, keystore: keystore.New()}
	s.setKMSProvider(&fakeKmsProvider{
		decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) { return dataKey, nil, nil },
	})

	resp, err := s.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{
		SecretEnvelope: env,
	})
	require.NoError(t, err)
	require.Equal(t, wantPub, resp.PublicKey)
	require.Empty(t, resp.AttestationDocument)
}

func TestGetPublicKey_AttestsDerivedKey_Nitro(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x2a}, 32)
	env, secretKey := newEd25519Envelope(t, dataKey)
	wantPublicKey, err := secretKey.PublicKey()
	require.NoError(t, err)
	wantDocument := []byte("attestation-document")

	ks := keystore.New()
	require.NoError(t, ks.Set(envelopeCacheKey(env), secretKey))
	ctrl := gomock.NewController(t)
	enclaveProvider := enclavePvd.NewMockProvider(ctrl)
	enclaveProvider.EXPECT().
		Attest(wantPublicKey).
		Return(wantDocument, nil)
	s := &Service{
		nitroEnclaveEnabled: true,
		keystore:            ks,
		enclavePvd:          enclaveProvider,
	}

	resp, err := s.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{
		SecretEnvelope: env,
	})

	require.NoError(t, err)
	require.Equal(t, wantPublicKey, resp.PublicKey)
	require.Equal(t, wantDocument, resp.AttestationDocument)
}

func TestGetPublicKey_FailsClosedWhenAttestationFails_Nitro(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x2a}, 32)
	env, secretKey := newEd25519Envelope(t, dataKey)
	wantPublicKey, err := secretKey.PublicKey()
	require.NoError(t, err)

	ks := keystore.New()
	require.NoError(t, ks.Set(envelopeCacheKey(env), secretKey))
	ctrl := gomock.NewController(t)
	enclaveProvider := enclavePvd.NewMockProvider(ctrl)
	enclaveProvider.EXPECT().
		Attest(wantPublicKey).
		Return(nil, errors.New("NSM failure detail"))
	s := &Service{
		nitroEnclaveEnabled: true,
		keystore:            ks,
		enclavePvd:          enclaveProvider,
	}

	resp, err := s.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{
		SecretEnvelope: env,
	})

	require.Nil(t, resp)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Contains(t, err.Error(), "failed to attest public key")
	require.NotContains(t, err.Error(), "NSM failure detail")
}

func TestGetPublicKey_FailsWhenEnclaveProviderIsNil_Nitro(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x2a}, 32)
	env, secretKey := newEd25519Envelope(t, dataKey)

	ks := keystore.New()
	require.NoError(t, ks.Set(envelopeCacheKey(env), secretKey))
	s := &Service{nitroEnclaveEnabled: true, keystore: ks}

	resp, err := s.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{
		SecretEnvelope: env,
	})

	require.Nil(t, resp)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Contains(t, err.Error(), "enclave provider is nil while nitro enclave is enabled")
}

func TestSignMessage_WithSecretEnvelope_BadPrivateKey(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x2a}, 32)
	s := &Service{nitroEnclaveEnabled: false, keystore: keystore.New()}
	s.setKMSProvider(&fakeKmsProvider{
		decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) { return dataKey, nil, nil },
	})
	env := &pb.SecretEnvelope{
		Algorithm:           pb.Algorithm_ALGORITHM_ED25519,
		KmsEncryptedDataKey: []byte("kms-ciphertext"),
		EncryptedPrivateKey: []byte("not-a-valid-gcm-ciphertext"),
		Nonce:               []byte("bad-nonce"),
	}
	_, err := s.SignMessage(context.Background(), &pb.SignMessageRequest{
		SecretEnvelope: env, Message: []byte("hello"),
	})
	require.Error(t, err)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Equal(t, "key recovery failed", status.Convert(err).Message())
}

// TestNitroNilEnclaveProvider verifies the defensive guard on both envelope
// paths: with Nitro enabled, an enclave provider is required to decrypt KMS
// CiphertextForRecipient with the in-memory RSA private key. A nil provider
// must fail with FailedPrecondition rather than dereferencing nil.
func TestNitroNilEnclaveProvider(t *testing.T) {
	t.Run("generateEnvelope", func(t *testing.T) {
		s := &Service{nitroEnclaveEnabled: true, enclavePvd: nil, keystore: keystore.New()}
		s.setKMSProvider(&fakeKmsProvider{
			generateDataKey: func(_ context.Context) ([]byte, []byte, []byte, error) {
				return nil, []byte("kms-cipher-blob"), []byte("recipient-ct"), nil
			},
		})
		_, _, err := s.generateEnvelope(context.Background(), pb.Algorithm_ALGORITHM_ED25519)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		require.Contains(t, err.Error(), "enclave provider is nil")
	})
	t.Run("decryptDataKeyFromKMS", func(t *testing.T) {
		s := &Service{nitroEnclaveEnabled: true, enclavePvd: nil, keystore: keystore.New()}
		s.setKMSProvider(&fakeKmsProvider{
			decrypt: func(_ context.Context, _ []byte) ([]byte, []byte, error) {
				return nil, []byte("recipient-ct"), nil
			},
		})
		_, err := s.decryptDataKeyFromKMS(context.Background(), []byte("kms-ct"))
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		require.Contains(t, err.Error(), "enclave provider is nil")
	})
}

// TestReadRequests_RequireSecretEnvelope_Protovalidate pins the
// (buf.validate.field).required = true annotation on the read RPCs: a request
// missing secret_envelope must be rejected by the protovalidate interceptor.
// Guards against the required annotation being dropped, which would let a
// bare request reach the handler and dereference a nil envelope.
func TestReadRequests_RequireSecretEnvelope_Protovalidate(t *testing.T) {
	v, err := protovalidate.New()
	require.NoError(t, err)
	env := &pb.SecretEnvelope{
		Algorithm:           pb.Algorithm_ALGORITHM_ED25519,
		KmsEncryptedDataKey: []byte("k"),
		EncryptedPrivateKey: []byte("p"),
		Nonce:               []byte("n"),
	}

	t.Run("GetPublicKey", func(t *testing.T) {
		require.NoError(t, v.Validate(&pb.GetPublicKeyRequest{SecretEnvelope: env}))
		require.Error(t, v.Validate(&pb.GetPublicKeyRequest{}))
	})
	t.Run("SignMessage", func(t *testing.T) {
		msg := []byte("m")
		require.NoError(t, v.Validate(&pb.SignMessageRequest{Message: msg, SecretEnvelope: env}))
		require.Error(t, v.Validate(&pb.SignMessageRequest{Message: msg}))
	})
}
