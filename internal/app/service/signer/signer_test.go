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

package signer

import (
	"context"
	"errors"
	"testing"

	"github.com/circlefin/arc-remote-signer/internal/app/provider/awskms"
	"github.com/circlefin/arc-remote-signer/internal/app/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/app/provider/secrets"
	"github.com/circlefin/arc-remote-signer/internal/common/crypto"
	commonAES "github.com/circlefin/arc-remote-signer/internal/common/crypto/aes"
	"github.com/circlefin/arc-remote-signer/internal/common/crypto/rand"
	"github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto/ed25519"
	pb "github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testKeyID    = "00000000-0000-0000-0000-000000000000"
	testSecretID = "test-secret-id"
)

// SignerServiceTestSuite contains the test suite for the signer service.
type SignerServiceTestSuite struct {
	suite.Suite
	ctrl           *gomock.Controller
	mockEnclavePvd *enclave.MockEnclaveServiceClient
	mockSecretsPvd *secrets.MockProvider
	mockAWSKMSPvd  *awskms.MockProvider

	initializedService       *Service
	uninitializedService     *Service
	testMessage              []byte
	testPublicKey            []byte
	testSignature            []byte
	testEncryptedKeyMaterial pb.EncryptedKeyMaterial
}

// SetupTest runs before each test method.
func (s *SignerServiceTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.mockEnclavePvd = enclave.NewMockEnclaveServiceClient(s.ctrl)
	s.mockSecretsPvd = secrets.NewMockProvider(s.ctrl)
	s.mockAWSKMSPvd = awskms.NewMockProvider(s.ctrl)

	s.testMessage = []byte("test message")

	key, err := ed25519.New()
	s.Require().NoError(err)
	pub, err := key.PublicKey()
	s.Require().NoError(err)

	keyBytes, err := key.Serialize()
	s.Require().NoError(err)

	dataKey := rand.MustGenerateRandomBytes(32)

	encryptedDataKey, nonce, err := commonAES.EncryptGCM(dataKey, keyBytes)
	s.Require().NoError(err)

	s.testEncryptedKeyMaterial = pb.EncryptedKeyMaterial{
		EncryptedPrivateKey:     encryptedDataKey,
		EnclaveEncryptedDataKey: dataKey,
		Nonce:                   nonce,
	}

	s.testPublicKey = pub
	sig, err := key.SignMessage(s.testMessage)
	s.Require().NoError(err)
	s.testSignature = sig

	s.setupUninitializedService()
	s.setupInitializedService()
}

// TearDownTest runs after each test method.
func (s *SignerServiceTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *SignerServiceTestSuite) TestLogger() {
	logger := getLogger()
	s.Require().NotNil(logger)
}

// TestSign tests the Sign RPC method.
func (s *SignerServiceTestSuite) TestSign() {
	tests := []struct {
		name          string
		request       *pb.SignRequest
		mockSetup     func()
		wantError     bool
		wantCode      codes.Code
		wantMessage   string
		wantSignature []byte
		service       *Service
	}{
		{
			name: "successful sign",
			request: &pb.SignRequest{
				Message: []byte(s.testMessage),
			},
			mockSetup: func() {
				s.mockEnclavePvd.EXPECT().
					SignMessage(gomock.Any(), &pb.SignMessageRequest{
						Algorithm:            pb.Algorithm_ALGORITHM_ED25519,
						EncryptedKeyMaterial: &s.testEncryptedKeyMaterial,
						Message:              s.testMessage,
					}).
					Return(&pb.SignMessageResponse{
						Signature: s.testSignature,
					}, nil).
					Times(1)
			},
			wantError:     false,
			wantCode:      codes.OK,
			wantMessage:   "",
			wantSignature: s.testSignature,
			service:       s.initializedService,
		},
		{
			name:          "nil request",
			request:       nil,
			mockSetup:     func() {},
			wantError:     true,
			wantCode:      codes.InvalidArgument,
			wantMessage:   errInvalidRequest,
			wantSignature: nil,
			service:       s.initializedService,
		},
		{
			name:          "empty message",
			request:       &pb.SignRequest{Message: []byte{}},
			mockSetup:     func() {},
			wantError:     true,
			wantCode:      codes.InvalidArgument,
			wantMessage:   errEmptyMessage,
			wantSignature: nil,
			service:       s.initializedService,
		},
		{
			name:          "nil message",
			request:       &pb.SignRequest{Message: nil},
			mockSetup:     func() {},
			wantError:     true,
			wantCode:      codes.InvalidArgument,
			wantMessage:   errEmptyMessage,
			wantSignature: nil,
			service:       s.initializedService,
		},
		{
			name: "enclave provider error",
			request: &pb.SignRequest{
				Message: s.testMessage,
			},
			mockSetup: func() {
				s.mockEnclavePvd.EXPECT().
					SignMessage(gomock.Any(), &pb.SignMessageRequest{
						Algorithm:            pb.Algorithm_ALGORITHM_ED25519,
						EncryptedKeyMaterial: &s.testEncryptedKeyMaterial,
						Message:              s.testMessage,
					}).
					Return(nil, errors.New("enclave error")).
					Times(1)
			},
			wantError:     true,
			wantCode:      codes.Unknown,
			wantMessage:   "failed to sign message",
			wantSignature: nil,
			service:       s.initializedService,
		},
		{
			name: "sign message with uninitialized service",
			request: &pb.SignRequest{
				Message: s.testMessage,
			},
			mockSetup:     func() {},
			wantError:     true,
			wantCode:      codes.Internal,
			wantMessage:   "service is not initialized",
			wantSignature: nil,
			service:       s.uninitializedService,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			tt.mockSetup()
			resp, err := tt.service.Sign(context.Background(), tt.request)
			if tt.wantError {
				s.Require().Error(err)
				s.Require().Nil(resp)
				if tt.wantCode == codes.Unknown {
					s.Require().Contains(err.Error(), tt.wantMessage)
				} else {
					grpcErr, ok := status.FromError(err)
					s.Require().True(ok)
					s.Require().Equal(tt.wantCode, grpcErr.Code())
					s.Require().Contains(grpcErr.Message(), tt.wantMessage)
				}
			} else {
				s.Require().NoError(err)
				s.Require().NotNil(resp)
				s.Require().Equal([]byte(tt.wantSignature), resp.Signature)
			}
		})
	}
}

// TestPublicKey tests the PublicKey RPC method.
func (s *SignerServiceTestSuite) TestPublicKey() {
	tests := []struct {
		name        string
		wantError   bool
		wantCode    codes.Code
		wantMessage string
		wantPublic  []byte
		service     *Service
	}{
		{
			name:        "successful public key retrieval",
			wantError:   false,
			wantCode:    codes.OK,
			wantMessage: "",
			wantPublic:  s.testPublicKey,
			service:     s.initializedService,
		},
		{
			name:        "retrieval with uninitialized service",
			wantError:   true,
			wantCode:    codes.Internal,
			wantMessage: "service is not initialized",
			wantPublic:  nil,
			service:     s.uninitializedService,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			ctrl := gomock.NewController(s.T())
			defer ctrl.Finish()

			resp, err := tt.service.PublicKey(context.Background(), &pb.PublicKeyRequest{})
			if tt.wantError {
				s.Require().Error(err)
				s.Require().Nil(resp)
				grpcErr, ok := status.FromError(err)
				s.Require().True(ok)
				s.Require().Equal(tt.wantCode, grpcErr.Code())
				s.Require().Contains(grpcErr.Message(), tt.wantMessage)
			} else {
				s.Require().NoError(err)
				s.Require().NotNil(resp)
				s.Require().Equal(tt.wantPublic, resp.PublicKey)
			}
		})
	}
}

// TestServiceInitialization tests the service initialization logic.
func (s *SignerServiceTestSuite) TestServiceInitialization() {
	hdr := header{
		CipherKey:  s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey,
		CipherData: s.testEncryptedKeyMaterial.EncryptedPrivateKey,
		Nonce:      s.testEncryptedKeyMaterial.Nonce,
	}

	headerBytes, err := hdr.MarshalBinary()
	if err != nil {
		s.Require().NoError(err)
	}

	tests := []struct {
		name        string
		secretValue []byte
		mockSetup   func()
		wantError   bool
		wantMessage string
	}{
		{
			name:        "initialize with existing secret",
			secretValue: headerBytes,
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return(headerBytes, nil).
					Times(1)

				s.mockAWSKMSPvd.EXPECT().Decrypt(gomock.Any(), s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey).Return(s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey, s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey, nil)

				s.mockEnclavePvd.EXPECT().
					GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{
						Algorithm:            pb.Algorithm_ALGORITHM_ED25519,
						EncryptedKeyMaterial: &s.testEncryptedKeyMaterial,
					}).
					Return(&pb.GetPublicKeyResponse{
						PublicKey: s.testPublicKey,
					}, nil).
					Times(1)
			},
			wantError:   false,
			wantMessage: "",
		},
		{
			name:        "get secret error",
			secretValue: []byte{},
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return(nil, errors.New("secrets error")).
					Times(1)
			},
			wantError:   true,
			wantMessage: "failed to get secret",
		},
		{
			name:        "get public key error",
			secretValue: headerBytes,
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return(headerBytes, nil).
					Times(1)

				s.mockAWSKMSPvd.EXPECT().Decrypt(gomock.Any(), s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey).Return(s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey, s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey, nil)

				s.mockEnclavePvd.EXPECT().
					GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{
						Algorithm:            pb.Algorithm_ALGORITHM_ED25519,
						EncryptedKeyMaterial: &s.testEncryptedKeyMaterial,
					}).
					Return(nil, errors.New("get public key error")).
					Times(1)
			},
			wantError:   true,
			wantMessage: "failed to get public key",
		},
		{
			name:        "decrypt data key error",
			secretValue: headerBytes,
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return(headerBytes, nil).
					Times(1)

				s.mockAWSKMSPvd.EXPECT().Decrypt(gomock.Any(), s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey).Return(nil, nil, errors.New("decrypt data key error"))
			},
			wantError:   true,
			wantMessage: "failed to decrypt data key",
		},
		{
			name:        "key generation error",
			secretValue: []byte{},
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return([]byte{}, nil).
					Times(1)

				s.mockAWSKMSPvd.EXPECT().
					GenerateDataKey(gomock.Any()).
					Return(s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey, s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey, s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GenerateKey(gomock.Any(), &pb.GenerateKeyRequest{
						Algorithm:               pb.Algorithm_ALGORITHM_ED25519,
						EnclaveEncryptedDataKey: s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey,
					}).
					Return(nil, errors.New("generation error")).
					Times(1)
			},
			wantError:   true,
			wantMessage: "failed to generate key",
		},
		{
			name:        "update secret error",
			secretValue: []byte{},
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return([]byte{}, nil).
					Times(1)

				s.mockAWSKMSPvd.EXPECT().
					GenerateDataKey(gomock.Any()).
					Return(s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey, s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey, s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GenerateKey(gomock.Any(), &pb.GenerateKeyRequest{
						Algorithm:               pb.Algorithm_ALGORITHM_ED25519,
						EnclaveEncryptedDataKey: s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey,
					}).
					Return(&pb.GenerateKeyResponse{
						EncryptedPrivateKey: s.testEncryptedKeyMaterial.EncryptedPrivateKey,
						PublicKey:           s.testPublicKey,
						Nonce:               s.testEncryptedKeyMaterial.Nonce,
					}, nil)

				s.mockSecretsPvd.EXPECT().
					Update(gomock.Any(), testKeyID, headerBytes).
					Return("", errors.New("update secret error")).
					Times(1)
			},
			wantError:   true,
			wantMessage: "failed to update secret",
		},
		{
			name:        "generate data key error",
			secretValue: []byte{},
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return([]byte{}, nil).
					Times(1)

				s.mockAWSKMSPvd.EXPECT().
					GenerateDataKey(gomock.Any()).
					Return(nil, nil, nil, errors.New("generate data key error")).
					Times(1)
			},
			wantError:   true,
			wantMessage: "failed to generate data key",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			ctrl := gomock.NewController(s.T())
			defer ctrl.Finish()
			config := &Config{
				Algorithm: crypto.AlgorithmEd25519,
				KeyID:     testKeyID,
			}
			tt.mockSetup()
			service, err := New(context.Background(), false, config, s.mockSecretsPvd, s.mockEnclavePvd, s.mockAWSKMSPvd)
			if tt.wantError {
				s.Require().Error(err)
				s.Require().Nil(service)
				s.Require().Contains(err.Error(), tt.wantMessage)
			} else {
				s.Require().NoError(err)
				s.Require().NotNil(service)
			}
		})
	}
}

func (s *SignerServiceTestSuite) setupUninitializedService() {
	s.uninitializedService = &Service{
		secretPvd:  s.mockSecretsPvd,
		enclavePvd: s.mockEnclavePvd,
		awskmsPvd:  s.mockAWSKMSPvd,
		algorithm:  pb.Algorithm_ALGORITHM_ED25519,
		cache:      newCache(),
	}
}

func (s *SignerServiceTestSuite) setupInitializedService() {
	s.mockSecretsPvd.EXPECT().
		Get(gomock.Any(), testKeyID).
		Return(nil, nil)

	s.mockAWSKMSPvd.EXPECT().
		GenerateDataKey(gomock.Any()).
		Return(s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey, s.testEncryptedKeyMaterial.EncryptedPrivateKey, s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey, nil)

	s.mockEnclavePvd.EXPECT().
		GenerateKey(gomock.Any(), &pb.GenerateKeyRequest{
			Algorithm:               pb.Algorithm_ALGORITHM_ED25519,
			EnclaveEncryptedDataKey: s.testEncryptedKeyMaterial.EnclaveEncryptedDataKey,
		}).
		Return(&pb.GenerateKeyResponse{
			EncryptedPrivateKey: s.testEncryptedKeyMaterial.EncryptedPrivateKey,
			PublicKey:           s.testPublicKey,
			Nonce:               s.testEncryptedKeyMaterial.Nonce,
		}, nil)

	hdr := header{
		CipherKey:  s.testEncryptedKeyMaterial.EncryptedPrivateKey,
		CipherData: s.testEncryptedKeyMaterial.EncryptedPrivateKey,
		Nonce:      s.testEncryptedKeyMaterial.Nonce,
	}

	headerBytes, err := hdr.MarshalBinary()
	if err != nil {
		s.Require().NoError(err)
	}

	s.mockSecretsPvd.EXPECT().
		Update(gomock.Any(), testKeyID, headerBytes).
		Return(testSecretID, nil)

	cfg := NewConfig()
	initializedService, err := New(context.Background(), false, cfg, s.mockSecretsPvd, s.mockEnclavePvd, s.mockAWSKMSPvd)
	s.Require().NoError(err)
	s.initializedService = initializedService
}

// Run the test suite.
func TestSignerServiceTestSuite(t *testing.T) {
	suite.Run(t, new(SignerServiceTestSuite))
}
