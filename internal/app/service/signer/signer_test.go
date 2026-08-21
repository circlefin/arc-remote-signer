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
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

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

	initializedService   *Service
	uninitializedService *Service
	testMessage          []byte
	testPublicKey        []byte
	testAttestationDoc   []byte
	testSignature        []byte
	refreshCancel        context.CancelFunc
	// testEnvelope is the wrapped key the enclave returns from GenerateKey and
	// accepts on the read RPCs; testStoredSecret is its persisted header form.
	testEnvelope     *pb.SecretEnvelope
	testStoredSecret []byte
}

// SetupTest runs before each test method.
func (s *SignerServiceTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.mockEnclavePvd = enclave.NewMockEnclaveServiceClient(s.ctrl)
	s.mockSecretsPvd = secrets.NewMockProvider(s.ctrl)

	s.testMessage = []byte("test message")

	key, err := ed25519.New()
	s.Require().NoError(err)
	pub, err := key.PublicKey()
	s.Require().NoError(err)
	keyBytes, err := key.Serialize()
	s.Require().NoError(err)

	dataKey := rand.MustGenerateRandomBytes(32)
	encryptedPrivateKey, nonce, err := commonAES.EncryptGCM(dataKey, keyBytes)
	s.Require().NoError(err)

	s.testEnvelope = &pb.SecretEnvelope{
		Algorithm:           pb.Algorithm_ALGORITHM_ED25519,
		KmsEncryptedDataKey: []byte("kms-encrypted-data-key"),
		EncryptedPrivateKey: encryptedPrivateKey,
		Nonce:               nonce,
	}
	storedBytes, err := headerFromSecretEnvelope(s.testEnvelope).MarshalBinary()
	s.Require().NoError(err)
	s.testStoredSecret = storedBytes

	s.testPublicKey = pub
	now := time.Now()
	targetCertificate := testCertificate(s.T(), now.Add(-time.Hour), now.Add(24*time.Hour), 10)
	rootCertificate := testCertificate(s.T(), now.Add(-24*time.Hour), now.Add(365*24*time.Hour), 11)
	s.testAttestationDoc = testAttestationDocument(s.T(), targetCertificate, rootCertificate)
	sig, err := key.SignMessage(s.testMessage)
	s.Require().NoError(err)
	s.testSignature = sig

	s.setupUninitializedService()
	s.setupInitializedService()
}

// TearDownTest runs after each test method.
func (s *SignerServiceTestSuite) TearDownTest() {
	if s.refreshCancel != nil {
		s.refreshCancel()
	}
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
						SecretEnvelope: s.testEnvelope,
						Message:        s.testMessage,
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
						SecretEnvelope: s.testEnvelope,
						Message:        s.testMessage,
					}).
					Return(nil, errors.New("enclave error")).
					Times(1)
			},
			wantError:     true,
			wantCode:      codes.Internal,
			wantMessage:   errSignMessage,
			wantSignature: nil,
			service:       s.initializedService,
		},
		{
			name: "enclave provider gRPC error",
			request: &pb.SignRequest{
				Message: s.testMessage,
			},
			mockSetup: func() {
				s.mockEnclavePvd.EXPECT().
					SignMessage(gomock.Any(), &pb.SignMessageRequest{
						SecretEnvelope: s.testEnvelope,
						Message:        s.testMessage,
					}).
					Return(nil, status.Error(codes.PermissionDenied, "sensitive enclave details")).
					Times(1)
			},
			wantError:     true,
			wantCode:      codes.Internal,
			wantMessage:   errSignMessage,
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
				grpcErr, ok := status.FromError(err)
				s.Require().True(ok)
				s.Require().Equal(tt.wantCode, grpcErr.Code())
				s.Require().Equal(tt.wantMessage, grpcErr.Message())
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
		name         string
		mockSetup    func()
		wantError    bool
		wantCode     codes.Code
		wantMessage  string
		wantPublic   []byte
		wantDocument []byte
		service      *Service
	}{
		{
			name:         "successful public key retrieval",
			mockSetup:    func() {},
			wantError:    false,
			wantCode:     codes.OK,
			wantMessage:  "",
			wantPublic:   s.testPublicKey,
			wantDocument: s.testAttestationDoc,
			service:      s.initializedService,
		},
		{
			name:        "retrieval with uninitialized service",
			mockSetup:   func() {},
			wantError:   true,
			wantCode:    codes.Internal,
			wantMessage: "service is not initialized",
			wantPublic:  nil,
			service:     s.uninitializedService,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			tt.mockSetup()
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
				s.Require().Equal(tt.wantDocument, resp.AttestationDocument)
			}
		})
	}
}

func (s *SignerServiceTestSuite) TestPublicKeyReturnsCachedAttestation() {
	firstResponse, err := s.initializedService.PublicKey(context.Background(), &pb.PublicKeyRequest{})
	s.Require().NoError(err)
	secondResponse, err := s.initializedService.PublicKey(context.Background(), &pb.PublicKeyRequest{})

	s.Require().NoError(err)
	s.Require().Equal(s.testAttestationDoc, firstResponse.AttestationDocument)
	s.Require().Equal(firstResponse.AttestationDocument, secondResponse.AttestationDocument)
	firstResponse.PublicKey[0] ^= 0xff
	firstResponse.AttestationDocument[0] ^= 0xff
	s.Require().Equal(s.testPublicKey, secondResponse.PublicKey)
	s.Require().Equal(s.testAttestationDoc, secondResponse.AttestationDocument)
}

func (s *SignerServiceTestSuite) TestRefreshAttestationUpdatesCachedDocument() {
	now := time.Now()
	newTarget := testCertificate(s.T(), now.Add(-time.Hour), now.Add(48*time.Hour), 12)
	newRoot := testCertificate(s.T(), now.Add(-24*time.Hour), now.Add(365*24*time.Hour), 13)
	newDocument := testAttestationDocument(s.T(), newTarget, newRoot)
	s.mockEnclavePvd.EXPECT().
		GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{SecretEnvelope: s.testEnvelope}).
		Return(&pb.GetPublicKeyResponse{
			PublicKey:           s.testPublicKey,
			AttestationDocument: newDocument,
		}, nil)

	validity, err := s.initializedService.refreshAttestation(context.Background())

	s.Require().NoError(err)
	s.Require().Equal(newTarget.NotAfter, validity.notAfter)
	response, err := s.initializedService.PublicKey(context.Background(), &pb.PublicKeyRequest{})
	s.Require().NoError(err)
	s.Require().Equal(newDocument, response.AttestationDocument)
}

func (s *SignerServiceTestSuite) TestRefreshAttestationKeepsCacheOnKeyMismatch() {
	s.mockEnclavePvd.EXPECT().
		GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{SecretEnvelope: s.testEnvelope}).
		Return(&pb.GetPublicKeyResponse{
			PublicKey:           []byte("different-public-key"),
			AttestationDocument: s.testAttestationDoc,
		}, nil)

	_, err := s.initializedService.refreshAttestation(context.Background())

	s.Require().ErrorContains(err, "different public key")
	response, responseErr := s.initializedService.PublicKey(context.Background(), &pb.PublicKeyRequest{})
	s.Require().NoError(responseErr)
	s.Require().Equal(s.testAttestationDoc, response.AttestationDocument)
}

func (s *SignerServiceTestSuite) TestRefreshAttestationKeepsCurrentExpiryWhenNewExpiryIsEarlier() {
	now := time.Now()
	shorterTarget := testCertificate(s.T(), now.Add(-time.Hour), now.Add(12*time.Hour), 16)
	shorterDocument := testAttestationDocument(s.T(), shorterTarget)
	s.mockEnclavePvd.EXPECT().
		GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{SecretEnvelope: s.testEnvelope}).
		Return(&pb.GetPublicKeyResponse{
			PublicKey:           s.testPublicKey,
			AttestationDocument: shorterDocument,
		}, nil)

	validity, err := s.initializedService.refreshAttestation(context.Background())

	s.Require().NoError(err)
	s.Require().True(validity.notAfter.After(shorterTarget.NotAfter))
	response, responseErr := s.initializedService.PublicKey(context.Background(), &pb.PublicKeyRequest{})
	s.Require().NoError(responseErr)
	s.Require().Equal(s.testAttestationDoc, response.AttestationDocument)
}

func (s *SignerServiceTestSuite) TestStartAttestationRefresh_UpdatesCachedDocument() {
	now := time.Now()
	newTarget := testCertificate(s.T(), now.Add(-time.Hour), now.Add(48*time.Hour), 17)
	newDocument := testAttestationDocument(s.T(), newTarget)
	s.mockEnclavePvd.EXPECT().
		GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{SecretEnvelope: s.testEnvelope}).
		Return(&pb.GetPublicKeyResponse{
			PublicKey:           s.testPublicKey,
			AttestationDocument: newDocument,
		}, nil)

	// Schedule the first refresh shortly after the loop starts. The assertion
	// polls the cached response instead of sleeping for a fixed interval.
	s.initializedService.loadedKeyMu.Lock()
	s.initializedService.loadedKey.attestationValidity = attestationValidity{
		notBefore: now.Add(-time.Second),
		notAfter:  now.Add(375 * time.Millisecond),
	}
	s.initializedService.loadedKeyMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.initializedService.startAttestationRefresh(ctx)

	s.Require().Eventually(func() bool {
		response, err := s.initializedService.PublicKey(context.Background(), &pb.PublicKeyRequest{})
		return err == nil && bytes.Equal(response.AttestationDocument, newDocument)
	}, 2*time.Second, 10*time.Millisecond)
}

func (s *SignerServiceTestSuite) TestGetPublicKey_RejectsEmptyResponse() {
	tests := []struct {
		name     string
		response *pb.GetPublicKeyResponse
	}{
		{name: "nil response", response: nil},
		{name: "empty public key", response: &pb.GetPublicKeyResponse{}},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			s.mockEnclavePvd.EXPECT().
				GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{SecretEnvelope: s.testEnvelope}).
				Return(tt.response, nil)

			response, err := s.uninitializedService.getPublicKey(context.Background(), s.testEnvelope)

			s.Require().Nil(response)
			s.Require().ErrorContains(err, "enclave GetPublicKey returned empty public key")
		})
	}
}

func (s *SignerServiceTestSuite) TestPublicKeyRejectsExpiredAttestation() {
	s.initializedService.loadedKeyMu.Lock()
	s.initializedService.loadedKey.attestationValidity.notAfter = time.Now().Add(-time.Second)
	s.initializedService.loadedKeyMu.Unlock()

	response, err := s.initializedService.PublicKey(context.Background(), &pb.PublicKeyRequest{})

	s.Require().Nil(response)
	s.Require().Equal(codes.Unavailable, status.Code(err))
	s.Require().ErrorContains(err, "attestation document is expired")
}

// TestServiceInitialization tests the service initialization logic.
func (s *SignerServiceTestSuite) TestServiceInitialization() {
	tests := []struct {
		name         string
		mockSetup    func()
		wantError    bool
		wantMessage  string
		wantPublic   []byte
		wantDocument []byte
	}{
		{
			name: "initialize with existing secret",
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return(s.testStoredSecret, nil).
					Times(1)

				// No host-side KMS Decrypt: the enclave decrypts the envelope.
				s.mockEnclavePvd.EXPECT().
					GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{
						SecretEnvelope: s.testEnvelope,
					}).
					Return(&pb.GetPublicKeyResponse{
						PublicKey:           s.testPublicKey,
						AttestationDocument: s.testAttestationDoc,
					}, nil).
					Times(1)
			},
			wantError:    false,
			wantPublic:   s.testPublicKey,
			wantDocument: s.testAttestationDoc,
		},
		{
			name: "get secret error",
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
			name: "get public key error",
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return(s.testStoredSecret, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{
						SecretEnvelope: s.testEnvelope,
					}).
					Return(nil, errors.New("get public key error")).
					Times(1)
			},
			wantError:   true,
			wantMessage: "failed to get public key",
		},
		{
			name: "existing secret: malformed attestation document",
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return(s.testStoredSecret, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{
						SecretEnvelope: s.testEnvelope,
					}).
					Return(&pb.GetPublicKeyResponse{
						PublicKey:           s.testPublicKey,
						AttestationDocument: []byte("not-cbor"),
					}, nil).
					Times(1)
			},
			wantError:   true,
			wantMessage: "failed to parse attestation document",
		},
		{
			name: "existing secret: expired attestation document",
			mockSetup: func() {
				now := time.Now()
				expiredCertificate := testCertificate(s.T(), now.Add(-2*time.Hour), now.Add(-time.Hour), 14)
				expiredDocument := testAttestationDocument(s.T(), expiredCertificate)
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return(s.testStoredSecret, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{
						SecretEnvelope: s.testEnvelope,
					}).
					Return(&pb.GetPublicKeyResponse{
						PublicKey:           s.testPublicKey,
						AttestationDocument: expiredDocument,
					}, nil).
					Times(1)
			},
			wantError:   true,
			wantMessage: errAttestationExpired,
		},
		{
			name: "existing secret: attestation certificate is not valid yet",
			mockSetup: func() {
				now := time.Now()
				futureCertificate := testCertificate(s.T(), now.Add(time.Hour), now.Add(2*time.Hour), 15)
				futureDocument := testAttestationDocument(s.T(), futureCertificate)
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return(s.testStoredSecret, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{
						SecretEnvelope: s.testEnvelope,
					}).
					Return(&pb.GetPublicKeyResponse{
						PublicKey:           s.testPublicKey,
						AttestationDocument: futureDocument,
					}, nil).
					Times(1)
			},
			wantError:   true,
			wantMessage: "attestation certificate is not valid yet",
		},
		{
			name: "existing secret: malformed header",
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return([]byte("not-a-valid-gob-header"), nil).
					Times(1)
			},
			wantError:   true,
			wantMessage: "failed to unmarshal header",
		},
		{
			name: "existing secret: algorithm mismatch",
			mockSetup: func() {
				// Stored header records BLS but the service is configured for Ed25519.
				mismatched, err := (&header{
					Algorithm:  pb.Algorithm_ALGORITHM_BLS,
					CipherKey:  s.testEnvelope.KmsEncryptedDataKey,
					CipherData: s.testEnvelope.EncryptedPrivateKey,
					Nonce:      s.testEnvelope.Nonce,
				}).MarshalBinary()
				s.Require().NoError(err)
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return(mismatched, nil).
					Times(1)
			},
			wantError:   true,
			wantMessage: "does not match configured algorithm",
		},
		{
			name: "bootstrap: key generation error",
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return([]byte{}, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GenerateKey(gomock.Any(), &pb.GenerateKeyRequest{
						Algorithm: pb.Algorithm_ALGORITHM_ED25519,
					}).
					Return(nil, errors.New("generation error")).
					Times(1)
			},
			wantError:   true,
			wantMessage: "failed to generate key",
		},
		{
			name: "bootstrap: missing secret envelope in response",
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return([]byte{}, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GenerateKey(gomock.Any(), &pb.GenerateKeyRequest{
						Algorithm: pb.Algorithm_ALGORITHM_ED25519,
					}).
					Return(&pb.GenerateKeyResponse{PublicKey: s.testPublicKey}, nil).
					Times(1)
			},
			wantError:   true,
			wantMessage: "no secret envelope",
		},
		{
			name: "bootstrap: empty public key in response",
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return([]byte{}, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GenerateKey(gomock.Any(), &pb.GenerateKeyRequest{
						Algorithm: pb.Algorithm_ALGORITHM_ED25519,
					}).
					Return(&pb.GenerateKeyResponse{SecretEnvelope: s.testEnvelope}, nil).
					Times(1)
			},
			wantError:   true,
			wantMessage: "empty public key",
		},
		{
			name: "bootstrap: incomplete secret envelope in response",
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return([]byte{}, nil).
					Times(1)

				// Envelope missing Nonce — must fail before the Secrets Manager write.
				incomplete := &pb.SecretEnvelope{
					Algorithm:           pb.Algorithm_ALGORITHM_ED25519,
					KmsEncryptedDataKey: s.testEnvelope.KmsEncryptedDataKey,
					EncryptedPrivateKey: s.testEnvelope.EncryptedPrivateKey,
				}
				s.mockEnclavePvd.EXPECT().
					GenerateKey(gomock.Any(), &pb.GenerateKeyRequest{
						Algorithm: pb.Algorithm_ALGORITHM_ED25519,
					}).
					Return(&pb.GenerateKeyResponse{PublicKey: s.testPublicKey, SecretEnvelope: incomplete}, nil).
					Times(1)
			},
			wantError:   true,
			wantMessage: "incomplete secret envelope",
		},
		{
			name: "bootstrap: attestation error",
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return([]byte{}, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GenerateKey(gomock.Any(), &pb.GenerateKeyRequest{
						Algorithm: pb.Algorithm_ALGORITHM_ED25519,
					}).
					Return(&pb.GenerateKeyResponse{
						PublicKey:      s.testPublicKey,
						SecretEnvelope: s.testEnvelope,
					}, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{
						SecretEnvelope: s.testEnvelope,
					}).
					Return(nil, errors.New("attestation error")).
					Times(1)
			},
			wantError:   true,
			wantMessage: "failed to get public key",
		},
		{
			name: "bootstrap: public key mismatch",
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return([]byte{}, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GenerateKey(gomock.Any(), &pb.GenerateKeyRequest{
						Algorithm: pb.Algorithm_ALGORITHM_ED25519,
					}).
					Return(&pb.GenerateKeyResponse{
						PublicKey:      s.testPublicKey,
						SecretEnvelope: s.testEnvelope,
					}, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{
						SecretEnvelope: s.testEnvelope,
					}).
					Return(&pb.GetPublicKeyResponse{
						PublicKey:           []byte("different-public-key"),
						AttestationDocument: s.testAttestationDoc,
					}, nil).
					Times(1)
			},
			wantError:   true,
			wantMessage: "enclave returned different public keys",
		},
		{
			name: "bootstrap: malformed attestation document",
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return([]byte{}, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GenerateKey(gomock.Any(), &pb.GenerateKeyRequest{
						Algorithm: pb.Algorithm_ALGORITHM_ED25519,
					}).
					Return(&pb.GenerateKeyResponse{
						PublicKey:      s.testPublicKey,
						SecretEnvelope: s.testEnvelope,
					}, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{
						SecretEnvelope: s.testEnvelope,
					}).
					Return(&pb.GetPublicKeyResponse{
						PublicKey:           s.testPublicKey,
						AttestationDocument: []byte("not-cbor"),
					}, nil).
					Times(1)
			},
			wantError:   true,
			wantMessage: "failed to parse attestation document",
		},
		{
			name: "bootstrap: update secret error",
			mockSetup: func() {
				s.mockSecretsPvd.EXPECT().
					Get(gomock.Any(), testKeyID).
					Return([]byte{}, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GenerateKey(gomock.Any(), &pb.GenerateKeyRequest{
						Algorithm: pb.Algorithm_ALGORITHM_ED25519,
					}).
					Return(&pb.GenerateKeyResponse{
						PublicKey:      s.testPublicKey,
						SecretEnvelope: s.testEnvelope,
					}, nil).
					Times(1)

				s.mockEnclavePvd.EXPECT().
					GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{
						SecretEnvelope: s.testEnvelope,
					}).
					Return(&pb.GetPublicKeyResponse{
						PublicKey:           s.testPublicKey,
						AttestationDocument: s.testAttestationDoc,
					}, nil).
					Times(1)

				s.mockSecretsPvd.EXPECT().
					Update(gomock.Any(), testKeyID, s.testStoredSecret).
					Return("", errors.New("update secret error")).
					Times(1)
			},
			wantError:   true,
			wantMessage: "failed to update secret",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			config := &Config{
				Algorithm: crypto.AlgorithmEd25519,
				KeyID:     testKeyID,
			}
			tt.mockSetup()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			service, err := New(ctx, config, s.mockSecretsPvd, s.mockEnclavePvd)
			if tt.wantError {
				s.Require().Error(err)
				s.Require().Nil(service)
				s.Require().Contains(err.Error(), tt.wantMessage)
			} else {
				s.Require().NoError(err)
				s.Require().NotNil(service)
				response, responseErr := service.PublicKey(context.Background(), &pb.PublicKeyRequest{})
				s.Require().NoError(responseErr)
				s.Require().Equal(tt.wantPublic, response.PublicKey)
				s.Require().Equal(tt.wantDocument, response.AttestationDocument)
			}
		})
	}
}

func (s *SignerServiceTestSuite) setupUninitializedService() {
	// loadedKey left nil to exercise the "service not initialized" path.
	s.uninitializedService = &Service{
		secretPvd:  s.mockSecretsPvd,
		enclavePvd: s.mockEnclavePvd,
		algorithm:  pb.Algorithm_ALGORITHM_ED25519,
	}
}

func (s *SignerServiceTestSuite) setupInitializedService() {
	// First boot: the enclave mints the key, the host persists the returned
	// envelope, and New retains the loaded key state for request handling.
	s.mockSecretsPvd.EXPECT().
		Get(gomock.Any(), testKeyID).
		Return(nil, nil)

	s.mockEnclavePvd.EXPECT().
		GenerateKey(gomock.Any(), &pb.GenerateKeyRequest{
			Algorithm: pb.Algorithm_ALGORITHM_ED25519,
		}).
		Return(&pb.GenerateKeyResponse{
			PublicKey:      s.testPublicKey,
			SecretEnvelope: s.testEnvelope,
		}, nil)

	s.mockEnclavePvd.EXPECT().
		GetPublicKey(gomock.Any(), &pb.GetPublicKeyRequest{
			SecretEnvelope: s.testEnvelope,
		}).
		Return(&pb.GetPublicKeyResponse{
			PublicKey:           s.testPublicKey,
			AttestationDocument: s.testAttestationDoc,
		}, nil)

	s.mockSecretsPvd.EXPECT().
		Update(gomock.Any(), testKeyID, s.testStoredSecret).
		Return(testSecretID, nil)

	cfg := NewConfig()
	ctx, cancel := context.WithCancel(context.Background())
	s.refreshCancel = cancel
	initializedService, err := New(ctx, cfg, s.mockSecretsPvd, s.mockEnclavePvd)
	s.Require().NoError(err)
	s.initializedService = initializedService
}

// Run the test suite.
func TestSignerServiceTestSuite(t *testing.T) {
	suite.Run(t, new(SignerServiceTestSuite))
}
