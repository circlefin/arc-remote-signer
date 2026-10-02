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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
	"github.com/stretchr/testify/require"
)

type testNSMSession struct {
	send   func(request.Request) (response.Response, error)
	closed bool
}

func (s *testNSMSession) Send(req request.Request) (response.Response, error) {
	return s.send(req)
}

func (s *testNSMSession) Close() error {
	s.closed = true
	return nil
}

func TestProvider_AttestBindsUserDataAndUsesNewSession(t *testing.T) {
	userData := []byte("validator-public-key")
	documents := [][]byte{[]byte("attestation-document-1"), []byte("attestation-document-2")}
	var gotRequests []*request.Attestation
	var sessions []*testNSMSession
	pvd := &provider{
		openSession: func() (nsmSession, error) {
			index := len(sessions)
			session := &testNSMSession{
				send: func(req request.Request) (response.Response, error) {
					gotRequests = append(gotRequests, req.(*request.Attestation))
					return response.Response{
						Attestation: &response.Attestation{Document: documents[index]},
					}, nil
				},
			}
			sessions = append(sessions, session)
			return session, nil
		},
	}

	firstDocument, err := pvd.Attest(userData)
	require.NoError(t, err)
	secondDocument, err := pvd.Attest(userData)

	require.NoError(t, err)
	require.Equal(t, documents[0], firstDocument)
	require.Equal(t, documents[1], secondDocument)
	require.Len(t, gotRequests, 2)
	require.Len(t, sessions, 2)
	for index := range gotRequests {
		require.Equal(t, userData, gotRequests[index].UserData)
		require.Empty(t, gotRequests[index].Nonce)
		require.Empty(t, gotRequests[index].PublicKey)
		require.True(t, sessions[index].closed)
	}

	documents[0][0] = 'X'
	require.Equal(t, []byte("attestation-document-1"), firstDocument)
}

func TestProvider_AttestRejectsInvalidResponse(t *testing.T) {
	tests := []struct {
		name     string
		openErr  error
		response response.Response
		sendErr  error
	}{
		{
			name:    "session open failure",
			openErr: errors.New("open failed"),
		},
		{
			name:    "send failure",
			sendErr: errors.New("send failed"),
		},
		{
			name:     "NSM error",
			response: response.Response{Error: response.ECInternalError},
		},
		{
			name:     "missing attestation",
			response: response.Response{},
		},
		{
			name: "empty document",
			response: response.Response{
				Attestation: &response.Attestation{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &testNSMSession{
				send: func(request.Request) (response.Response, error) {
					return tt.response, tt.sendErr
				},
			}
			pvd := &provider{
				openSession: func() (nsmSession, error) {
					return session, tt.openErr
				},
			}

			document, err := pvd.Attest([]byte("validator-public-key"))

			require.Error(t, err)
			require.Nil(t, document)
			require.Equal(t, tt.openErr == nil, session.closed)
		})
	}
}

func TestProvider_AttestKMSRecipientUsesRetainedRSAKeyAndFreshSession(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	require.NoError(t, err)
	documents := [][]byte{[]byte("attestation-document-1"), []byte("attestation-document-2")}
	var gotRequests []*request.Attestation
	var sessions []*testNSMSession
	gotProvider, err := newProvider(func() (nsmSession, error) {
		index := len(sessions)
		session := &testNSMSession{
			send: func(req request.Request) (response.Response, error) {
				gotRequests = append(gotRequests, req.(*request.Attestation))
				return response.Response{
					Attestation: &response.Attestation{Document: documents[index]},
				}, nil
			},
		}
		sessions = append(sessions, session)
		return session, nil
	}, privateKey)
	require.NoError(t, err)

	firstDocument, err := gotProvider.AttestKMSRecipient()
	require.NoError(t, err)
	secondDocument, err := gotProvider.AttestKMSRecipient()
	require.NoError(t, err)

	require.Equal(t, documents[0], firstDocument)
	require.Equal(t, documents[1], secondDocument)
	require.Len(t, gotRequests, 2)
	require.Len(t, sessions, 2)
	for index := range gotRequests {
		parsedPublicKey, err := x509.ParsePKIXPublicKey(gotRequests[index].PublicKey)
		require.NoError(t, err)
		require.Equal(t, &privateKey.PublicKey, parsedPublicKey)
		require.Empty(t, gotRequests[index].Nonce)
		require.Empty(t, gotRequests[index].UserData)
		require.True(t, sessions[index].closed)
	}
}

func TestProvider_AttestKMSRecipientRejectsInvalidResponse(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	require.NoError(t, err)
	tests := []struct {
		name     string
		response response.Response
		err      error
	}{
		{
			name: "send failure",
			err:  errors.New("send failed"),
		},
		{
			name:     "NSM error",
			response: response.Response{Error: response.ECInternalError},
		},
		{
			name:     "missing attestation",
			response: response.Response{},
		},
		{
			name: "empty document",
			response: response.Response{
				Attestation: &response.Attestation{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &testNSMSession{
				send: func(request.Request) (response.Response, error) {
					return tt.response, tt.err
				},
			}

			gotProvider, gotErr := newProvider(func() (nsmSession, error) { return session, nil }, privateKey)
			require.NoError(t, gotErr)

			document, gotErr := gotProvider.AttestKMSRecipient()
			require.Error(t, gotErr)
			require.Nil(t, document)
			require.True(t, session.closed)
		})
	}
}

func TestNewProvider_RejectsNilPrivateKey(t *testing.T) {
	gotProvider, err := newProvider(nil, nil)

	require.Error(t, err)
	require.Nil(t, gotProvider)
}
