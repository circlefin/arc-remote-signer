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

package awskms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseAmazonRootCAPoolRejectsInvalidBundles(t *testing.T) {
	firstBlock, remaining := pem.Decode(amazonRootCAPEM)
	require.NotNil(t, firstBlock)
	firstCertificate := pem.EncodeToMemory(firstBlock)

	foreignCertificate := newForeignKMSCertificate(t)
	foreignRoot := newForeignRootCertificate(t)
	tests := map[string]struct {
		bundle  []byte
		message string
	}{
		"leading data": {
			bundle:  append([]byte("unexpected data\n"), amazonRootCAPEM...),
			message: "invalid PEM data",
		},
		"data between certificates": {
			bundle: bytes.Join(
				[][]byte{firstCertificate, []byte("unexpected data\n"), remaining},
				nil,
			),
			message: "invalid PEM data",
		},
		"malformed block before certificates": {
			bundle: append(
				[]byte("-----BEGIN BROKEN-----\nunexpected data\n-----END BROKEN-----\n"),
				amazonRootCAPEM...,
			),
			message: "invalid PEM data",
		},
		"non-certificate block": {
			bundle:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("key")}),
			message: `invalid PEM block "PRIVATE KEY"`,
		},
		"PEM headers": {
			bundle: pem.EncodeToMemory(&pem.Block{
				Type:    "CERTIFICATE",
				Headers: map[string]string{"Header": "value"},
				Bytes:   firstBlock.Bytes,
			}),
			message: `invalid PEM block "CERTIFICATE"`,
		},
		"invalid certificate": {
			bundle:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("certificate")}),
			message: "parse Amazon root CA certificate",
		},
		"certificate is not self-signed": {
			bundle: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: foreignCertificate.Raw,
			}),
			message: "certificate is not self-signed",
		},
		"wrong certificate count": {
			bundle:  firstCertificate,
			message: "contains 1 certificates, expected 5",
		},
		"unapproved self-signed root": {
			bundle: append(
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreignRoot.Raw}),
				remaining...,
			),
			message: "unapproved SHA-256 fingerprint",
		},
		"leading space": {
			bundle:  append([]byte(" "), amazonRootCAPEM...),
			message: "invalid PEM data",
		},
		"leading unicode whitespace": {
			bundle:  append([]byte("\u00a0"), amazonRootCAPEM...),
			message: "invalid PEM data",
		},
		"space between certificates": {
			bundle:  bytes.Join([][]byte{firstCertificate, []byte(" "), remaining}, nil),
			message: "invalid PEM data",
		},
		"bare carriage return between certificates": {
			bundle:  bytes.Join([][]byte{firstCertificate, []byte("\r"), remaining}, nil),
			message: "invalid PEM data",
		},
		"blank line between certificates": {
			bundle:  bytes.Join([][]byte{firstCertificate, []byte("\n"), remaining}, nil),
			message: "invalid PEM data",
		},
		"missing final line ending": {
			bundle:  bytes.TrimSuffix(amazonRootCAPEM, []byte("\n")),
			message: "invalid PEM data",
		},
		"trailing space": {
			bundle:  append(bytes.Clone(amazonRootCAPEM), ' '),
			message: "invalid PEM data",
		},
		"trailing tab": {
			bundle:  append(bytes.Clone(amazonRootCAPEM), '\t'),
			message: "invalid PEM data",
		},
		"trailing form feed": {
			bundle:  append(bytes.Clone(amazonRootCAPEM), '\f'),
			message: "invalid PEM data",
		},
		"trailing unicode whitespace": {
			bundle:  append(bytes.Clone(amazonRootCAPEM), []byte("\u00a0")...),
			message: "invalid PEM data",
		},
		"trailing blank line": {
			bundle:  append(bytes.Clone(amazonRootCAPEM), '\n'),
			message: "invalid PEM data",
		},
		"trailing garbage": {
			bundle:  append(bytes.Clone(amazonRootCAPEM), []byte("garbage")...),
			message: "invalid PEM data",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parseAmazonRootCAPool(tc.bundle)
			require.ErrorContains(t, err, tc.message)
		})
	}
}

func TestParseAmazonRootCAPoolAcceptsSupportedLineEndings(t *testing.T) {
	tests := map[string][]byte{
		"lf endings": amazonRootCAPEM,
		"crlf endings": bytes.ReplaceAll(
			amazonRootCAPEM,
			[]byte("\n"),
			[]byte("\r\n"),
		),
		"mixed LF and CRLF separators": bytes.Replace(
			amazonRootCAPEM,
			[]byte("\n-----BEGIN CERTIFICATE-----"),
			[]byte("\r\n-----BEGIN CERTIFICATE-----"),
			1,
		),
	}

	for name, bundle := range tests {
		t.Run(name, func(t *testing.T) {
			pool, err := parseAmazonRootCAPool(bundle)

			require.NoError(t, err)
			require.NotNil(t, pool)
		})
	}
}

func TestAmazonRootCAPoolVerifiesKMSCertificateChain(t *testing.T) {
	chainPEM, err := os.ReadFile("testdata/kms-us-east-1-chain.pem")
	require.NoError(t, err)

	var certificates []*x509.Certificate
	remaining := chainPEM
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		require.NotNil(t, block)
		require.Equal(t, "CERTIFICATE", block.Type)
		certificate, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		certificates = append(certificates, certificate)
		remaining = bytes.TrimSpace(rest)
	}
	require.Len(t, certificates, 2)

	roots, err := newAmazonRootCAPool()
	require.NoError(t, err)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(certificates[1])

	_, err = certificates[0].Verify(x509.VerifyOptions{
		DNSName:       "kms.us-east-1.amazonaws.com",
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Date(2026, time.September, 4, 0, 0, 0, 0, time.UTC),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err)
}

func TestAmazonRootCAPoolContainsApprovedRoots(t *testing.T) {
	expectedFingerprints := []string{
		"8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e",
		"1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4",
		"18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4",
		"e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092",
		"568d6905a2c88708a4b3025190edcfedb1974a606a13c6e5290fcb2ae63edab5",
	}

	var actualFingerprints []string
	var approvedRoots []*x509.Certificate
	remaining := amazonRootCAPEM
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		require.NotNil(t, block)
		require.Equal(t, "CERTIFICATE", block.Type)
		fingerprint := sha256.Sum256(block.Bytes)
		actualFingerprints = append(actualFingerprints, hex.EncodeToString(fingerprint[:]))
		certificate, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		approvedRoots = append(approvedRoots, certificate)
		remaining = rest
	}
	require.ElementsMatch(t, expectedFingerprints, actualFingerprints)

	roots, err := newAmazonRootCAPool()
	require.NoError(t, err)
	for _, certificate := range approvedRoots {
		_, err := certificate.Verify(x509.VerifyOptions{
			Roots:       roots,
			CurrentTime: certificate.NotBefore.Add(time.Hour),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		require.NoError(t, err)
	}
}

func TestAmazonRootCAPoolRejectsCertificateFromAnotherRoot(t *testing.T) {
	roots, err := newAmazonRootCAPool()
	require.NoError(t, err)

	leaf := newForeignKMSCertificate(t)
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName: "kms.us-east-1.amazonaws.com",
		Roots:   roots,
	})
	require.Error(t, err)
	var unknownAuthority x509.UnknownAuthorityError
	require.ErrorAs(t, err, &unknownAuthority)
}

func newForeignKMSCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	tlsCertificate := newForeignKMSTLSCertificate(t)
	leaf, err := x509.ParseCertificate(tlsCertificate.Certificate[0])
	require.NoError(t, err)
	return leaf
}

func newForeignKMSTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	root := createForeignRootCertificate(t, rootKey, now)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "kms.us-east-1.amazonaws.com"},
		DNSNames:     []string{"kms.us-east-1.amazonaws.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		root,
		&leafKey.PublicKey,
		rootKey,
	)
	require.NoError(t, err)
	return tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafKey,
	}
}

func newForeignRootCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return createForeignRootCertificate(t, rootKey, time.Now())
}

func createForeignRootCertificate(
	t *testing.T,
	rootKey *ecdsa.PrivateKey,
	now time.Time,
) *x509.Certificate {
	t.Helper()

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Foreign Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(
		rand.Reader,
		rootTemplate,
		rootTemplate,
		&rootKey.PublicKey,
		rootKey,
	)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	return root
}
