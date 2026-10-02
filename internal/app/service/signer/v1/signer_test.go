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

package v1

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	enclaveProvider "github.com/circlefin/arc-remote-signer/internal/app/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/app/provider/secrets"
	"github.com/circlefin/arc-remote-signer/internal/common/crypto"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func testEnvelope() *pb.SecretEnvelope {
	return &pb.SecretEnvelope{
		Algorithm:           pb.Algorithm_ALGORITHM_ED25519,
		KmsEncryptedDataKey: []byte("kms-ciphertext"),
		EncryptedPrivateKey: []byte("private-ciphertext"),
		Nonce:               []byte("nonce"),
	}
}

func TestNew_GeneratesAndPersistsThroughInitialize(t *testing.T) {
	ctrl := gomock.NewController(t)
	secretPvd := secrets.NewMockProvider(ctrl)
	enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	envelope := testEnvelope()
	publicKey := []byte("public-key")
	cfg := &Config{Algorithm: crypto.AlgorithmEd25519, KeyID: "key-id"}
	headerBytes, err := headerFromSecretEnvelope(envelope).MarshalBinary()
	require.NoError(t, err)
	secretPvd.EXPECT().Get(gomock.Any(), cfg.KeyID).Return(nil, nil)
	secretPvd.EXPECT().Update(gomock.Any(), cfg.KeyID, headerBytes).Return("secret-id", nil)
	initialize := func(
		_ context.Context,
		existing *pb.SecretEnvelope,
		generate pb.Algorithm,
	) (*pb.InitializeResponse, error) {
		require.Nil(t, existing)
		require.Equal(t, pb.Algorithm_ALGORITHM_ED25519, generate)
		return &pb.InitializeResponse{PublicKey: publicKey, SecretEnvelope: envelope}, nil
	}

	service, err := New(context.Background(), cfg, secretPvd, enclavePvd, initialize)

	require.NoError(t, err)
	resp, err := service.PublicKey(context.Background(), &pb.PublicKeyRequest{})
	require.NoError(t, err)
	require.Equal(t, publicKey, resp.GetPublicKey())
}

func TestNew_RecoversStoredKeyThroughInitialize(t *testing.T) {
	ctrl := gomock.NewController(t)
	secretPvd := secrets.NewMockProvider(ctrl)
	enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	envelope := testEnvelope()
	stored, err := headerFromSecretEnvelope(envelope).MarshalBinary()
	require.NoError(t, err)
	cfg := &Config{Algorithm: crypto.AlgorithmEd25519, KeyID: "key-id"}
	secretPvd.EXPECT().Get(gomock.Any(), cfg.KeyID).Return(stored, nil)
	initialize := func(
		_ context.Context,
		existing *pb.SecretEnvelope,
		generate pb.Algorithm,
	) (*pb.InitializeResponse, error) {
		require.Equal(t, envelope, existing)
		require.Equal(t, pb.Algorithm_ALGORITHM_UNSPECIFIED, generate)
		return &pb.InitializeResponse{PublicKey: []byte("public-key")}, nil
	}

	service, err := New(context.Background(), cfg, secretPvd, enclavePvd, initialize)

	require.NoError(t, err)
	require.NotNil(t, service)
}

func TestNew_InitializationFailureDoesNotPublishService(t *testing.T) {
	ctrl := gomock.NewController(t)
	secretPvd := secrets.NewMockProvider(ctrl)
	enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	cfg := &Config{Algorithm: crypto.AlgorithmEd25519, KeyID: "key-id"}
	secretPvd.EXPECT().Get(gomock.Any(), cfg.KeyID).Return(nil, nil)
	initialize := func(
		context.Context,
		*pb.SecretEnvelope,
		pb.Algorithm,
	) (*pb.InitializeResponse, error) {
		return nil, errors.New("initialize failed")
	}

	service, err := New(context.Background(), cfg, secretPvd, enclavePvd, initialize)

	require.Nil(t, service)
	require.ErrorContains(t, err, "initialize failed")
}

func TestSign_ForwardsOnlyMessageAfterInitialization(t *testing.T) {
	ctrl := gomock.NewController(t)
	enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	service := &Service{
		enclavePvd: enclavePvd,
		loadedKey:  &keyState{publicKey: []byte("public-key")},
	}
	message := []byte("message")
	signature := []byte("signature")
	enclavePvd.EXPECT().
		SignMessage(gomock.Any(), &pb.SignMessageRequest{Message: message}).
		Return(&pb.SignMessageResponse{Signature: signature}, nil)

	resp, err := service.Sign(context.Background(), &pb.SignRequest{Message: message})

	require.NoError(t, err)
	require.Equal(t, signature, resp.GetSignature())
}

func TestSign_ValidatesRequestAndReadyState(t *testing.T) {
	service := &Service{}
	_, err := service.Sign(context.Background(), nil)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = service.Sign(context.Background(), &pb.SignRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = service.Sign(context.Background(), &pb.SignRequest{Message: []byte("message")})
	require.Equal(t, codes.Internal, status.Code(err))
}

func TestRefreshAttestation_UpdatesCachedDocument(t *testing.T) {
	ctrl := gomock.NewController(t)
	enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	now := time.Now()
	currentCertificate := testCertificate(t, now.Add(-time.Hour), now.Add(12*time.Hour), 20)
	newCertificate := testCertificate(t, now.Add(-time.Hour), now.Add(24*time.Hour), 21)
	currentDocument := testAttestationDocument(t, currentCertificate)
	newDocument := testAttestationDocument(t, newCertificate)
	currentValidity, err := parseAttestationValidity(currentDocument)
	require.NoError(t, err)
	publicKey := []byte("public-key")
	service := &Service{
		enclavePvd: enclavePvd,
		loadedKey: &keyState{
			publicKey:           publicKey,
			attestationDocument: currentDocument,
			attestationValidity: currentValidity,
		},
	}
	enclavePvd.EXPECT().
		GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{}).
		Return(&pb.GetPublicKeyResponse{
			PublicKey:           publicKey,
			AttestationDocument: newDocument,
		}, nil)

	validity, err := service.refreshAttestation(context.Background())

	require.NoError(t, err)
	require.Equal(t, newCertificate.NotAfter, validity.notAfter)
	response, err := service.PublicKey(context.Background(), &pb.PublicKeyRequest{})
	require.NoError(t, err)
	require.Equal(t, newDocument, response.GetAttestationDocument())
}

func TestNew_RejectsMalformedAttestation(t *testing.T) {
	ctrl := gomock.NewController(t)
	secretPvd := secrets.NewMockProvider(ctrl)
	enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	cfg := &Config{Algorithm: crypto.AlgorithmEd25519, KeyID: "key-id"}
	secretPvd.EXPECT().Get(gomock.Any(), cfg.KeyID).Return(nil, nil)
	initialize := func(
		context.Context,
		*pb.SecretEnvelope,
		pb.Algorithm,
	) (*pb.InitializeResponse, error) {
		return &pb.InitializeResponse{
			PublicKey:           []byte("public-key"),
			AttestationDocument: []byte("not-cbor"),
			SecretEnvelope:      testEnvelope(),
		}, nil
	}

	service, err := New(context.Background(), cfg, secretPvd, enclavePvd, initialize)

	require.Nil(t, service)
	require.ErrorContains(t, err, "failed to parse attestation document")
}

func TestNew_RejectsExpiredAttestation(t *testing.T) {
	ctrl := gomock.NewController(t)
	secretPvd := secrets.NewMockProvider(ctrl)
	enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	cfg := &Config{Algorithm: crypto.AlgorithmEd25519, KeyID: "key-id"}
	now := time.Now()
	expiredCertificate := testCertificate(t, now.Add(-2*time.Hour), now.Add(-time.Hour), 22)
	expiredDocument := testAttestationDocument(t, expiredCertificate)
	secretPvd.EXPECT().Get(gomock.Any(), cfg.KeyID).Return(nil, nil)
	initialize := func(
		context.Context,
		*pb.SecretEnvelope,
		pb.Algorithm,
	) (*pb.InitializeResponse, error) {
		return &pb.InitializeResponse{
			PublicKey:           []byte("public-key"),
			AttestationDocument: expiredDocument,
			SecretEnvelope:      testEnvelope(),
		}, nil
	}

	service, err := New(context.Background(), cfg, secretPvd, enclavePvd, initialize)

	require.Nil(t, service)
	require.ErrorContains(t, err, errAttestationExpired)
}

func TestNew_RejectsStoredAlgorithmMismatchBeforeInitialize(t *testing.T) {
	ctrl := gomock.NewController(t)
	secretPvd := secrets.NewMockProvider(ctrl)
	enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	envelope := testEnvelope()
	mismatched, err := (&header{
		Algorithm:  pb.Algorithm_ALGORITHM_BLS,
		CipherKey:  envelope.KmsEncryptedDataKey,
		CipherData: envelope.EncryptedPrivateKey,
		Nonce:      envelope.Nonce,
	}).MarshalBinary()
	require.NoError(t, err)
	cfg := &Config{Algorithm: crypto.AlgorithmEd25519, KeyID: "key-id"}
	secretPvd.EXPECT().Get(gomock.Any(), cfg.KeyID).Return(mismatched, nil)
	initializeCalled := false
	initialize := func(
		context.Context,
		*pb.SecretEnvelope,
		pb.Algorithm,
	) (*pb.InitializeResponse, error) {
		initializeCalled = true
		return nil, nil
	}

	service, err := New(context.Background(), cfg, secretPvd, enclavePvd, initialize)

	require.Nil(t, service)
	require.ErrorContains(t, err, "does not match configured algorithm")
	require.False(t, initializeCalled)
}

func TestNew_RejectsIncompleteGeneratedEnvelope(t *testing.T) {
	ctrl := gomock.NewController(t)
	secretPvd := secrets.NewMockProvider(ctrl)
	enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	cfg := &Config{Algorithm: crypto.AlgorithmEd25519, KeyID: "key-id"}
	secretPvd.EXPECT().Get(gomock.Any(), cfg.KeyID).Return(nil, nil)
	incomplete := testEnvelope()
	incomplete.Nonce = nil
	initialize := func(
		context.Context,
		*pb.SecretEnvelope,
		pb.Algorithm,
	) (*pb.InitializeResponse, error) {
		return &pb.InitializeResponse{
			PublicKey:      []byte("public-key"),
			SecretEnvelope: incomplete,
		}, nil
	}

	service, err := New(context.Background(), cfg, secretPvd, enclavePvd, initialize)

	require.Nil(t, service)
	require.ErrorContains(t, err, "incomplete secret envelope")
}

func TestNew_SecretsManagerUpdateFailureDoesNotPublishService(t *testing.T) {
	ctrl := gomock.NewController(t)
	secretPvd := secrets.NewMockProvider(ctrl)
	enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	envelope := testEnvelope()
	stored, err := headerFromSecretEnvelope(envelope).MarshalBinary()
	require.NoError(t, err)
	cfg := &Config{Algorithm: crypto.AlgorithmEd25519, KeyID: "key-id"}
	secretPvd.EXPECT().Get(gomock.Any(), cfg.KeyID).Return(nil, nil)
	secretPvd.EXPECT().
		Update(gomock.Any(), cfg.KeyID, stored).
		Return("", errors.New("update failed"))
	initialize := func(
		context.Context,
		*pb.SecretEnvelope,
		pb.Algorithm,
	) (*pb.InitializeResponse, error) {
		return &pb.InitializeResponse{
			PublicKey:      []byte("public-key"),
			SecretEnvelope: envelope,
		}, nil
	}

	service, err := New(context.Background(), cfg, secretPvd, enclavePvd, initialize)

	require.Nil(t, service)
	require.ErrorContains(t, err, "failed to update secret")
}

func TestPublicKey_ReturnsImmutableCachedAttestation(t *testing.T) {
	publicKey := []byte("public-key")
	document := []byte("attestation")
	service := &Service{
		loadedKey: &keyState{
			publicKey:           bytes.Clone(publicKey),
			attestationDocument: bytes.Clone(document),
		},
	}

	first, err := service.PublicKey(context.Background(), &pb.PublicKeyRequest{})
	require.NoError(t, err)
	first.PublicKey[0] ^= 0xff
	first.AttestationDocument[0] ^= 0xff
	second, err := service.PublicKey(context.Background(), &pb.PublicKeyRequest{})

	require.NoError(t, err)
	require.Equal(t, publicKey, second.GetPublicKey())
	require.Equal(t, document, second.GetAttestationDocument())
}

func TestPublicKey_RejectsUninitializedService(t *testing.T) {
	response, err := (&Service{}).PublicKey(context.Background(), &pb.PublicKeyRequest{})

	require.Nil(t, response)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Equal(t, errServiceNotInitialized, status.Convert(err).Message())
}

func TestPublicKey_RejectsExpiredAttestation(t *testing.T) {
	service := &Service{
		loadedKey: &keyState{
			publicKey: []byte("public-key"),
			attestationValidity: attestationValidity{
				notBefore: time.Now().Add(-2 * time.Hour),
				notAfter:  time.Now().Add(-time.Second),
			},
		},
	}

	response, err := service.PublicKey(context.Background(), &pb.PublicKeyRequest{})

	require.Nil(t, response)
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.Equal(t, errAttestationExpired, status.Convert(err).Message())
}

func TestSign_SanitizesEnclaveError(t *testing.T) {
	ctrl := gomock.NewController(t)
	enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	service := &Service{
		enclavePvd: enclavePvd,
		loadedKey:  &keyState{publicKey: []byte("public-key")},
	}
	message := []byte("message")
	enclavePvd.EXPECT().
		SignMessage(gomock.Any(), &pb.SignMessageRequest{Message: message}).
		Return(nil, status.Error(codes.PermissionDenied, "sensitive enclave details"))

	response, err := service.Sign(context.Background(), &pb.SignRequest{Message: message})

	require.Nil(t, response)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Equal(t, errSignMessage, status.Convert(err).Message())
	require.NotContains(t, status.Convert(err).Message(), "sensitive enclave details")
}

func TestRefreshAttestation_KeepsCacheOnPublicKeyMismatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	document := []byte("current-attestation")
	currentValidity := attestationValidity{notAfter: time.Now().Add(24 * time.Hour)}
	service := &Service{
		enclavePvd: enclavePvd,
		loadedKey: &keyState{
			publicKey:           []byte("public-key"),
			attestationDocument: document,
			attestationValidity: currentValidity,
		},
	}
	enclavePvd.EXPECT().
		GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{}).
		Return(&pb.GetPublicKeyResponse{
			PublicKey:           []byte("different-public-key"),
			AttestationDocument: document,
		}, nil)

	validity, err := service.refreshAttestation(context.Background())

	require.ErrorContains(t, err, "different public key")
	require.Equal(t, currentValidity, validity)
	response, responseErr := service.PublicKey(context.Background(), &pb.PublicKeyRequest{})
	require.NoError(t, responseErr)
	require.Equal(t, document, response.GetAttestationDocument())
}

func TestRefreshAttestation_KeepsCurrentExpiryWhenNewExpiryIsEarlier(t *testing.T) {
	ctrl := gomock.NewController(t)
	enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
	now := time.Now()
	currentCertificate := testCertificate(t, now.Add(-time.Hour), now.Add(24*time.Hour), 23)
	shorterCertificate := testCertificate(t, now.Add(-time.Hour), now.Add(12*time.Hour), 24)
	currentDocument := testAttestationDocument(t, currentCertificate)
	shorterDocument := testAttestationDocument(t, shorterCertificate)
	currentValidity, err := parseAttestationValidity(currentDocument)
	require.NoError(t, err)
	service := &Service{
		enclavePvd: enclavePvd,
		loadedKey: &keyState{
			publicKey:           []byte("public-key"),
			attestationDocument: currentDocument,
			attestationValidity: currentValidity,
		},
	}
	enclavePvd.EXPECT().
		GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{}).
		Return(&pb.GetPublicKeyResponse{
			PublicKey:           []byte("public-key"),
			AttestationDocument: shorterDocument,
		}, nil)

	validity, err := service.refreshAttestation(context.Background())

	require.NoError(t, err)
	require.Equal(t, currentValidity, validity)
	response, responseErr := service.PublicKey(context.Background(), &pb.PublicKeyRequest{})
	require.NoError(t, responseErr)
	require.Equal(t, currentDocument, response.GetAttestationDocument())
}

func TestGetPublicKey_RejectsEmptyResponse(t *testing.T) {
	tests := map[string]*pb.GetPublicKeyResponse{
		"nil response":     nil,
		"empty public key": {},
	}

	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			enclavePvd := enclaveProvider.NewMockEnclaveServiceClient(ctrl)
			service := &Service{enclavePvd: enclavePvd}
			enclavePvd.EXPECT().
				GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{}).
				Return(response, nil)

			result, err := service.getPublicKey(context.Background())

			require.Nil(t, result)
			require.ErrorContains(t, err, "enclave GetPublicKey returned empty public key")
		})
	}
}
