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
	"context"
	"fmt"
	"testing"

	commonAES "github.com/circlefin/arc-remote-signer/internal/common/crypto/aes"
	"github.com/circlefin/arc-remote-signer/internal/common/crypto/rand"
	enclaveCrypto "github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	aesCrypto "github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto/aes"
	enclavePvd "github.com/circlefin/arc-remote-signer/internal/enclave/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/keystore"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type EnclaveServiceTestSuite struct {
	suite.Suite
	ctrl      *gomock.Controller
	keystore  *keystore.MockProvider
	enclave   *enclavePvd.MockProvider
	service   *Service
	neService *Service

	dataKey          []byte
	secretKey        enclaveCrypto.Key
	encryptedKey     []byte
	nonce            []byte
	secretCacheKey   []byte
	encryptedKeyMtrl *pb.EncryptedKeyMaterial
}

func (s *EnclaveServiceTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.keystore = keystore.NewMockProvider(s.ctrl)
	s.enclave = enclavePvd.NewMockProvider(s.ctrl)

	s.service = New(false, s.keystore, s.enclave)
	s.neService = New(true, s.keystore, s.enclave)

	var err error
	s.dataKey = rand.MustGenerateRandomBytes(32)
	s.secretKey, err = enclaveCrypto.NewSecretKey(enclaveCrypto.AlgorithmEd25519)
	s.Require().NoError(err)

	secretKeyBytes, err := s.secretKey.Serialize()
	s.Require().NoError(err)
	s.encryptedKey, s.nonce, err = commonAES.EncryptGCM(s.dataKey, secretKeyBytes)
	s.Require().NoError(err)

	s.secretCacheKey = buildCacheKey(s.encryptedKey, s.dataKey, s.nonce)
	s.encryptedKeyMtrl = &pb.EncryptedKeyMaterial{
		EncryptedPrivateKey:     s.encryptedKey,
		EnclaveEncryptedDataKey: s.dataKey,
		Nonce:                   s.nonce,
	}
}

func (s *EnclaveServiceTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *EnclaveServiceTestSuite) TestGetAttestationDocument() {
	s.enclave.EXPECT().AttestationDocument().Return([]byte("doc"))

	resp, err := s.service.GetAttestation(context.Background(), &pb.GetAttestationRequest{})
	s.NoError(err)
	s.NotNil(resp)
	s.Equal([]byte("doc"), resp.AttestationDocument)

	withoutEnclave := New(false, s.keystore, nil)
	resp, err = withoutEnclave.GetAttestation(context.Background(), &pb.GetAttestationRequest{})
	s.Error(err)
	s.Equal(codes.FailedPrecondition, status.Code(err))
	s.Nil(resp)
}

func (s *EnclaveServiceTestSuite) TestGenerateKey_NilRequest() {
	resp, err := s.service.GenerateKey(context.Background(), nil)

	s.Nil(resp)
	s.Error(err)
	s.Equal(codes.InvalidArgument, status.Code(err))
	s.Contains(err.Error(), "request is nil")
}

func (s *EnclaveServiceTestSuite) TestGenerateKey_InvalidAlgorithm() {
	resp, err := s.service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		Algorithm: pb.Algorithm_ALGORITHM_UNSPECIFIED,
	})

	s.Nil(resp)
	s.Error(err)
	s.Equal(codes.InvalidArgument, status.Code(err))
}

func (s *EnclaveServiceTestSuite) TestGenerateKey_Success() {
	s.keystore.EXPECT().Get(s.dataKey).Return(nil)
	s.keystore.EXPECT().Set(s.dataKey, gomock.Any()).Return(nil)
	s.keystore.EXPECT().Set(gomock.Any(), gomock.Any()).Return(nil)

	resp, err := s.service.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		Algorithm:               pb.Algorithm_ALGORITHM_ED25519,
		EnclaveEncryptedDataKey: s.dataKey,
	})

	s.NoError(err)
	s.NotNil(resp)
	s.NotEmpty(resp.PublicKey)
	s.NotEmpty(resp.EncryptedPrivateKey)
	s.NotEmpty(resp.Nonce)
}

func (s *EnclaveServiceTestSuite) TestGenerateKey_LoadDataKeyErrorWithNitro() {
	s.keystore.EXPECT().Get(s.dataKey).Return(nil)
	s.enclave.EXPECT().DecryptKMSEnvelopedKey(s.dataKey).Return(nil, fmt.Errorf("decrypt failed"))

	resp, err := s.neService.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		Algorithm:               pb.Algorithm_ALGORITHM_ED25519,
		EnclaveEncryptedDataKey: s.dataKey,
	})

	s.Nil(resp)
	s.Error(err)
	s.Equal(codes.Internal, status.Code(err))
	s.ErrorContains(err, "failed to decrypt data key")
}

func (s *EnclaveServiceTestSuite) TestGetPublicKey_InvalidAlgorithm() {
	resp, err := s.service.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{
		Algorithm: pb.Algorithm_ALGORITHM_UNSPECIFIED,
	})

	s.Nil(resp)
	s.Error(err)
	s.Equal(codes.InvalidArgument, status.Code(err))
}

func (s *EnclaveServiceTestSuite) TestGetPublicKey_SuccessFromCache() {
	dataKeyObj, err := aesCrypto.Deserialize(s.dataKey)
	s.Require().NoError(err)

	s.keystore.EXPECT().Get(s.dataKey).Return(dataKeyObj)
	s.keystore.EXPECT().Get(s.secretCacheKey).Return(s.secretKey)

	resp, err := s.service.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{
		Algorithm:            pb.Algorithm_ALGORITHM_ED25519,
		EncryptedKeyMaterial: s.encryptedKeyMtrl,
	})

	s.NoError(err)
	s.NotNil(resp)
	s.NotEmpty(resp.PublicKey)
}

func (s *EnclaveServiceTestSuite) TestGetPublicKey_ResolveSecretKeyError() {
	s.keystore.EXPECT().Get(s.dataKey).Return(nil)
	s.keystore.EXPECT().Set(s.dataKey, gomock.Any()).Return(fmt.Errorf("set failed"))

	resp, err := s.service.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{
		Algorithm:            pb.Algorithm_ALGORITHM_ED25519,
		EncryptedKeyMaterial: s.encryptedKeyMtrl,
	})

	s.Nil(resp)
	s.Error(err)
	s.ErrorContains(err, "failed to cache data key")
}

func (s *EnclaveServiceTestSuite) TestGetPublicKey_NilEncryptedKeyMaterial() {
	resp, err := s.service.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{
		Algorithm:            pb.Algorithm_ALGORITHM_ED25519,
		EncryptedKeyMaterial: nil,
	})

	s.Nil(resp)
	s.Equal(codes.InvalidArgument, status.Code(err))
	s.ErrorContains(err, "encrypted key material is nil")
}

func (s *EnclaveServiceTestSuite) TestSignMessage_NilEncryptedKeyMaterial() {
	resp, err := s.service.SignMessage(context.Background(), &pb.SignMessageRequest{
		Algorithm:            pb.Algorithm_ALGORITHM_ED25519,
		EncryptedKeyMaterial: nil,
		Message:              []byte("x"),
	})

	s.Nil(resp)
	s.Equal(codes.InvalidArgument, status.Code(err))
	s.ErrorContains(err, "encrypted key material is nil")
}

func (s *EnclaveServiceTestSuite) TestSignMessage_InvalidAlgorithm() {
	resp, err := s.service.SignMessage(context.Background(), &pb.SignMessageRequest{
		Algorithm: pb.Algorithm_ALGORITHM_UNSPECIFIED,
		Message:   []byte("msg"),
	})

	s.Nil(resp)
	s.Error(err)
	s.Equal(codes.InvalidArgument, status.Code(err))
}

func (s *EnclaveServiceTestSuite) TestSignMessage_SuccessFromCache() {
	dataKeyObj, err := aesCrypto.Deserialize(s.dataKey)
	s.Require().NoError(err)

	message := []byte("payload")
	s.keystore.EXPECT().Get(s.dataKey).Return(dataKeyObj)
	s.keystore.EXPECT().Get(s.secretCacheKey).Return(s.secretKey)

	resp, err := s.service.SignMessage(context.Background(), &pb.SignMessageRequest{
		Algorithm:            pb.Algorithm_ALGORITHM_ED25519,
		EncryptedKeyMaterial: s.encryptedKeyMtrl,
		Message:              message,
	})

	s.NoError(err)
	s.NotNil(resp)
	s.NotEmpty(resp.Signature)
}

func (s *EnclaveServiceTestSuite) TestNilEnclavePvdWithNitroEnabled() {
	svc := New(true, s.keystore, nil)
	s.keystore.EXPECT().Get(s.dataKey).Return(nil).Times(3)

	s.Run("generate key returns failed precondition", func() {
		resp, err := svc.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
			Algorithm:               pb.Algorithm_ALGORITHM_ED25519,
			EnclaveEncryptedDataKey: s.dataKey,
		})

		s.Nil(resp)
		s.Error(err)
		s.Equal(codes.FailedPrecondition, status.Code(err))
		s.Contains(err.Error(), "enclave provider is nil while nitro enclave is enabled")
	})

	s.Run("get public key returns failed precondition", func() {
		resp, err := svc.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{
			Algorithm:            pb.Algorithm_ALGORITHM_ED25519,
			EncryptedKeyMaterial: s.encryptedKeyMtrl,
		})

		s.Nil(resp)
		s.Error(err)
		s.Equal(codes.FailedPrecondition, status.Code(err))
		s.Contains(err.Error(), "enclave provider is nil while nitro enclave is enabled")
	})

	s.Run("sign message returns failed precondition", func() {
		resp, err := svc.SignMessage(context.Background(), &pb.SignMessageRequest{
			Algorithm:            pb.Algorithm_ALGORITHM_ED25519,
			EncryptedKeyMaterial: s.encryptedKeyMtrl,
			Message:              []byte("payload"),
		})

		s.Nil(resp)
		s.Error(err)
		s.Equal(codes.FailedPrecondition, status.Code(err))
		s.Contains(err.Error(), "enclave provider is nil while nitro enclave is enabled")
	})
}

func (s *EnclaveServiceTestSuite) TestGenerateKey_NitroEnabledSuccess() {
	s.keystore.EXPECT().Get(s.dataKey).Return(nil)
	s.enclave.EXPECT().DecryptKMSEnvelopedKey(s.dataKey).Return(s.dataKey, nil)
	s.keystore.EXPECT().Set(s.dataKey, gomock.Any()).Return(nil)
	s.keystore.EXPECT().Set(gomock.Any(), gomock.Any()).Return(nil)

	resp, err := s.neService.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		Algorithm:               pb.Algorithm_ALGORITHM_ED25519,
		EnclaveEncryptedDataKey: s.dataKey,
	})

	s.NoError(err)
	s.NotNil(resp)
	s.NotEmpty(resp.PublicKey)
	s.NotEmpty(resp.EncryptedPrivateKey)
	s.NotEmpty(resp.Nonce)
}

func (s *EnclaveServiceTestSuite) TestGetPublicKey_NitroEnabledSuccess() {
	s.keystore.EXPECT().Get(s.dataKey).Return(nil)
	s.enclave.EXPECT().DecryptKMSEnvelopedKey(s.dataKey).Return(s.dataKey, nil)
	s.keystore.EXPECT().Set(s.dataKey, gomock.Any()).Return(nil)
	s.keystore.EXPECT().Get(s.secretCacheKey).Return(nil)
	s.keystore.EXPECT().Set(s.secretCacheKey, gomock.Any()).Return(nil)

	resp, err := s.neService.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{
		Algorithm:            pb.Algorithm_ALGORITHM_ED25519,
		EncryptedKeyMaterial: s.encryptedKeyMtrl,
	})

	s.NoError(err)
	s.NotNil(resp)
	s.NotEmpty(resp.PublicKey)
}

func (s *EnclaveServiceTestSuite) TestSignMessage_NitroEnabledSuccess() {
	s.keystore.EXPECT().Get(s.dataKey).Return(nil)
	s.enclave.EXPECT().DecryptKMSEnvelopedKey(s.dataKey).Return(s.dataKey, nil)
	s.keystore.EXPECT().Set(s.dataKey, gomock.Any()).Return(nil)
	s.keystore.EXPECT().Get(s.secretCacheKey).Return(nil)
	s.keystore.EXPECT().Set(s.secretCacheKey, gomock.Any()).Return(nil)

	message := []byte("payload")
	resp, err := s.neService.SignMessage(context.Background(), &pb.SignMessageRequest{
		Algorithm:            pb.Algorithm_ALGORITHM_ED25519,
		EncryptedKeyMaterial: s.encryptedKeyMtrl,
		Message:              message,
	})

	s.NoError(err)
	s.NotNil(resp)
	s.NotEmpty(resp.Signature)
}

func (s *EnclaveServiceTestSuite) TestLoadDataKey_CacheSetError() {
	s.keystore.EXPECT().Get(s.dataKey).Return(nil)
	s.keystore.EXPECT().Set(s.dataKey, gomock.Any()).Return(fmt.Errorf("set failed"))

	plainKey, err := s.service.loadDataKey(s.dataKey)
	s.Nil(plainKey)
	s.Error(err)
	s.ErrorContains(err, "failed to cache data key")
}

func (s *EnclaveServiceTestSuite) TestLoadDataKey_DeserializeError() {
	invalidKey := rand.MustGenerateRandomBytes(16)
	s.keystore.EXPECT().Get(invalidKey).Return(nil)

	plainKey, err := s.service.loadDataKey(invalidKey)
	s.Nil(plainKey)
	s.Error(err)
	s.Equal(codes.InvalidArgument, status.Code(err))
	s.ErrorContains(err, "failed to deserialize data key")
}

func (s *EnclaveServiceTestSuite) TestLoadSecretKey() {
	s.Run("DecryptError", func() {
		invalidEncrypted := rand.MustGenerateRandomBytes(32)
		invalidNonce := rand.MustGenerateRandomBytes(12)
		expectedCacheKey := buildCacheKey(invalidEncrypted, s.dataKey, invalidNonce)

		s.keystore.EXPECT().Get(expectedCacheKey).Return(nil)

		key, err := s.service.loadSecretKey(context.Background(), enclaveCrypto.AlgorithmEd25519, invalidEncrypted, s.dataKey, invalidNonce)
		s.Nil(key)
		s.Error(err)
		s.ErrorContains(err, "failed to decrypt secret key")
	})

	s.Run("DeserializeError", func() {
		// Encrypt garbage (10 bytes) — valid AES ciphertext, invalid Ed25519 key size.
		garbageKey := rand.MustGenerateRandomBytes(10)
		encryptedGarbage, nonce, err := commonAES.EncryptGCM(s.dataKey, garbageKey)
		s.Require().NoError(err)
		expectedCacheKey := buildCacheKey(encryptedGarbage, s.dataKey, nonce)

		s.keystore.EXPECT().Get(expectedCacheKey).Return(nil)

		key, err := s.service.loadSecretKey(
			context.Background(),
			enclaveCrypto.AlgorithmEd25519,
			encryptedGarbage,
			s.dataKey,
			nonce,
		)

		s.Nil(key)
		s.Require().Error(err)
		s.Equal(codes.InvalidArgument, status.Code(err))
		s.ErrorContains(err, "failed to deserialize secret key")
	})

	s.Run("CacheSetError", func() {
		s.keystore.EXPECT().Get(s.secretCacheKey).Return(nil)
		s.keystore.EXPECT().Set(s.secretCacheKey, gomock.Any()).Return(fmt.Errorf("set failed"))

		key, err := s.service.loadSecretKey(
			context.Background(),
			enclaveCrypto.AlgorithmEd25519,
			s.encryptedKey,
			s.dataKey,
			s.nonce,
		)

		s.Nil(key)
		s.Require().Error(err)
		s.Equal(codes.Internal, status.Code(err))
		s.ErrorContains(err, "failed to cache secret key")
	})
}

func (s *EnclaveServiceTestSuite) TestBuildCacheKey_DeterministicAndUnique() {
	k1 := buildCacheKey([]byte("a"), []byte("b"))
	k2 := buildCacheKey([]byte("a"), []byte("b"))
	k3 := buildCacheKey([]byte("ab"))

	s.Equal(k1, k2)
	s.NotEqual(k1, k3)
}

func (s *EnclaveServiceTestSuite) TestToAlgorithm() {
	tests := []struct {
		name      string
		input     pb.Algorithm
		wantAlg   enclaveCrypto.Algorithm
		wantError bool
	}{
		{"bls maps correctly", pb.Algorithm_ALGORITHM_BLS, enclaveCrypto.AlgorithmBLS, false},
		{"ed25519 maps correctly", pb.Algorithm_ALGORITHM_ED25519, enclaveCrypto.AlgorithmEd25519, false},
		{"unspecified returns error", pb.Algorithm_ALGORITHM_UNSPECIFIED, enclaveCrypto.Algorithm(""), true},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			alg, err := toAlgorithm(tt.input)
			if tt.wantError {
				s.Error(err)
			} else {
				s.NoError(err)
			}
			s.Equal(tt.wantAlg, alg)
		})
	}
}

func TestEnclaveServiceTestSuite(t *testing.T) {
	suite.Run(t, new(EnclaveServiceTestSuite))
}
