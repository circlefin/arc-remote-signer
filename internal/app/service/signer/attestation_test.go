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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestParseAttestationValidityUsesCertificateChainIntersection(t *testing.T) {
	now := time.Date(2026, time.August, 11, 10, 0, 0, 0, time.UTC)
	target := testCertificate(t, now.Add(-time.Hour), now.Add(12*time.Hour), 1)
	intermediate := testCertificate(t, now.Add(-2*time.Hour), now.Add(6*time.Hour), 2)
	root := testCertificate(t, now.Add(-24*time.Hour), now.Add(365*24*time.Hour), 3)
	document := testAttestationDocument(t, target, intermediate, root)

	validity, err := parseAttestationValidity(document)

	require.NoError(t, err)
	require.Equal(t, target.NotBefore, validity.notBefore)
	require.Equal(t, intermediate.NotAfter, validity.notAfter)
}

func TestParseAttestationValidityAcceptsUntaggedCOSESign1(t *testing.T) {
	now := time.Date(2026, time.August, 11, 10, 0, 0, 0, time.UTC)
	certificate := testCertificate(t, now.Add(-time.Hour), now.Add(12*time.Hour), 4)
	taggedDocument := testAttestationDocument(t, certificate)
	var tag cbor.RawTag
	require.NoError(t, cbor.Unmarshal(taggedDocument, &tag))

	validity, err := parseAttestationValidity(tag.Content)

	require.NoError(t, err)
	require.Equal(t, certificate.NotBefore, validity.notBefore)
	require.Equal(t, certificate.NotAfter, validity.notAfter)
}

func TestParseAttestationValidityRejectsMalformedDocument(t *testing.T) {
	_, err := parseAttestationValidity([]byte("not-cbor"))

	require.ErrorContains(t, err, "failed to decode COSE tag")
}

func TestParseAttestationValidityRejectsUnexpectedCOSETag(t *testing.T) {
	document, err := cbor.Marshal(cbor.RawTag{Number: 17, Content: []byte{}})
	require.NoError(t, err)

	_, err = parseAttestationValidity(document)

	require.ErrorContains(t, err, "unexpected COSE tag: 17")
}

func TestAttestationRefreshDelayUsesCertificateLifetime(t *testing.T) {
	validity := attestationValidity{
		notBefore: time.Date(2026, time.August, 11, 0, 0, 0, 0, time.UTC),
		notAfter:  time.Date(2026, time.August, 11, 10, 0, 0, 0, time.UTC),
	}

	delay := attestationRefreshDelay(validity.notBefore.Add(7*time.Hour), validity, false)

	require.Equal(t, time.Hour, delay)
}

func TestAttestationRefreshDelayBoundsRetries(t *testing.T) {
	validity := attestationValidity{
		notBefore: time.Date(2026, time.August, 11, 0, 0, 0, 0, time.UTC),
		notAfter:  time.Date(2026, time.August, 11, 10, 0, 0, 0, time.UTC),
	}

	require.Equal(t, attestationRefreshRetryCeiling, attestationRefreshDelay(validity.notAfter.Add(-time.Hour), validity, true))
	require.Equal(t, attestationRefreshRetryFloor, attestationRefreshDelay(validity.notAfter.Add(-time.Second), validity, true))
}

func testCertificate(t *testing.T, notBefore, notAfter time.Time, serial int64) *x509.Certificate {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "test-attestation"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate
}

func testAttestationDocument(t *testing.T, certificate *x509.Certificate, caBundle ...*x509.Certificate) []byte {
	t.Helper()

	encodedBundle := make([][]byte, 0, len(caBundle))
	for _, cert := range caBundle {
		encodedBundle = append(encodedBundle, cert.Raw)
	}
	payload, err := cbor.Marshal(map[string]any{
		"certificate": certificate.Raw,
		"cabundle":    encodedBundle,
	})
	require.NoError(t, err)
	sign1, err := cbor.Marshal([]any{[]byte{}, map[string]any{}, payload, []byte("signature")})
	require.NoError(t, err)
	document, err := cbor.Marshal(cbor.RawTag{Number: 18, Content: sign1})
	require.NoError(t, err)
	return document
}
