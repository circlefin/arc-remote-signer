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
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	coseSign1Tag                   = 18
	attestationRefreshRetryFloor   = 30 * time.Second
	attestationRefreshRetryCeiling = 5 * time.Minute
	attestationRefreshNumerator    = 4
	attestationRefreshDivisor      = 5
)

type attestationValidity struct {
	notBefore time.Time
	notAfter  time.Time
}

func (v attestationValidity) validateAt(now time.Time) error {
	if now.Before(v.notBefore) {
		return errors.New(errAttestationNotValidYet)
	}
	if !now.Before(v.notAfter) {
		return errors.New(errAttestationExpired)
	}
	return nil
}

type attestationPayload struct {
	Certificate []byte   `cbor:"certificate"`
	CABundle    [][]byte `cbor:"cabundle"`
}

func parseAttestationValidity(document []byte) (attestationValidity, error) {
	var tag cbor.RawTag
	err := cbor.Unmarshal(document, &tag)
	if err == nil {
		if tag.Number != coseSign1Tag {
			return attestationValidity{}, fmt.Errorf("unexpected COSE tag: %d", tag.Number)
		}
		document = tag.Content
	} else {
		var typeError *cbor.UnmarshalTypeError
		if !errors.As(err, &typeError) {
			return attestationValidity{}, fmt.Errorf("failed to decode COSE tag: %w", err)
		}
	}

	var sign1 []cbor.RawMessage
	if err := cbor.Unmarshal(document, &sign1); err != nil {
		return attestationValidity{}, fmt.Errorf("failed to decode COSE Sign1: %w", err)
	}
	if len(sign1) != 4 {
		return attestationValidity{}, errors.New("COSE Sign1 must contain four fields")
	}

	var payloadBytes []byte
	if err := cbor.Unmarshal(sign1[2], &payloadBytes); err != nil {
		return attestationValidity{}, fmt.Errorf("failed to decode attestation payload: %w", err)
	}
	var payload attestationPayload
	if err := cbor.Unmarshal(payloadBytes, &payload); err != nil {
		return attestationValidity{}, fmt.Errorf("failed to decode attestation fields: %w", err)
	}
	if len(payload.Certificate) == 0 {
		return attestationValidity{}, errors.New("attestation certificate is empty")
	}

	certificateData := make([][]byte, 0, len(payload.CABundle)+1)
	certificateData = append(certificateData, payload.Certificate)
	certificateData = append(certificateData, payload.CABundle...)

	var validity attestationValidity
	for _, data := range certificateData {
		certificate, err := x509.ParseCertificate(data)
		if err != nil {
			return attestationValidity{}, fmt.Errorf("failed to parse attestation certificate: %w", err)
		}
		if validity.notBefore.IsZero() || certificate.NotBefore.After(validity.notBefore) {
			validity.notBefore = certificate.NotBefore
		}
		if validity.notAfter.IsZero() || certificate.NotAfter.Before(validity.notAfter) {
			validity.notAfter = certificate.NotAfter
		}
	}
	return validity, nil
}

func attestationRefreshDelay(now time.Time, validity attestationValidity, retry bool) time.Duration {
	if !retry {
		lifetime := validity.notAfter.Sub(validity.notBefore)
		refreshAt := validity.notBefore.Add(lifetime * attestationRefreshNumerator / attestationRefreshDivisor)
		if now.Before(refreshAt) {
			return refreshAt.Sub(now)
		}
	}

	delay := validity.notAfter.Sub(now) / 2
	if delay < attestationRefreshRetryFloor {
		return attestationRefreshRetryFloor
	}
	if delay > attestationRefreshRetryCeiling {
		return attestationRefreshRetryCeiling
	}
	return delay
}
