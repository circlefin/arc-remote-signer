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
	"crypto/sha256"
	"crypto/x509"
	// The blank import enables the go:embed directive.
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	amazonRootCACount             = 5
	invalidAmazonRootCAPEMMessage = "amazon root CA bundle contains invalid PEM data"
)

var approvedAmazonRootCAFingerprints = map[string]struct{}{
	"8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e": {},
	"1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4": {},
	"18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4": {},
	"e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092": {},
	"568d6905a2c88708a4b3025190edcfedb1974a606a13c6e5290fcb2ae63edab5": {},
}

// amazonRootCAPEM contains the self-signed roots that Amazon Trust Services
// recommends for custom trust stores. The source is
// https://www.amazontrust.com/repository/.
//
//go:embed certs/amazon-trust-roots.pem
var amazonRootCAPEM []byte

func newAmazonRootCAPool() (*x509.CertPool, error) {
	return parseAmazonRootCAPool(amazonRootCAPEM)
}

func parseAmazonRootCAPool(bundle []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	remaining := bundle
	certificateCount := 0
	seenFingerprints := make(map[string]struct{}, amazonRootCACount)

	for len(remaining) > 0 {
		block, rest, err := decodeStrictPEMBlock(remaining)
		if err != nil {
			return nil, err
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("amazon root CA bundle contains invalid PEM block %q", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse Amazon root CA certificate: %w", err)
		}
		if err := certificate.CheckSignatureFrom(certificate); err != nil {
			return nil, fmt.Errorf("amazon root CA certificate is not self-signed: %w", err)
		}
		fingerprint := fmt.Sprintf("%x", sha256.Sum256(block.Bytes))
		if _, approved := approvedAmazonRootCAFingerprints[fingerprint]; !approved {
			return nil, fmt.Errorf(
				"amazon root CA certificate has unapproved SHA-256 fingerprint %s",
				fingerprint,
			)
		}
		if _, duplicate := seenFingerprints[fingerprint]; duplicate {
			return nil, fmt.Errorf(
				"amazon root CA bundle contains duplicate SHA-256 fingerprint %s",
				fingerprint,
			)
		}
		seenFingerprints[fingerprint] = struct{}{}
		pool.AddCert(certificate)
		certificateCount++
		remaining = rest
	}

	if certificateCount != amazonRootCACount {
		return nil, fmt.Errorf(
			"amazon root CA bundle contains %d certificates, expected %d",
			certificateCount,
			amazonRootCACount,
		)
	}
	return pool, nil
}

func decodeStrictPEMBlock(data []byte) (*pem.Block, []byte, error) {
	if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
		return nil, nil, errors.New(invalidAmazonRootCAPEMMessage)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, nil, errors.New(invalidAmazonRootCAPEMMessage)
	}
	beginMarker := []byte("-----BEGIN " + block.Type + "-----")
	if !bytes.HasPrefix(data, beginMarker) ||
		!hasSupportedLineEndingPrefix(data[len(beginMarker):]) {
		return nil, nil, errors.New(invalidAmazonRootCAPEMMessage)
	}
	consumed := data[:len(data)-len(rest)]
	if !hasSupportedLineEndingSuffix(consumed) {
		return nil, nil, errors.New(invalidAmazonRootCAPEMMessage)
	}
	if len(rest) > 0 && !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
		return nil, nil, errors.New(invalidAmazonRootCAPEMMessage)
	}
	return block, rest, nil
}

func hasSupportedLineEndingPrefix(data []byte) bool {
	return bytes.HasPrefix(data, []byte("\n")) ||
		bytes.HasPrefix(data, []byte("\r\n"))
}

func hasSupportedLineEndingSuffix(data []byte) bool {
	if bytes.HasSuffix(data, []byte("\r\n")) {
		return true
	}
	if !bytes.HasSuffix(data, []byte("\n")) {
		return false
	}
	return len(data) < 2 || data[len(data)-2] != '\r'
}
