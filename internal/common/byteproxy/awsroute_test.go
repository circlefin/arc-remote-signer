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

package byteproxy

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAWSRouteRoundTripPreservesPayload(t *testing.T) {
	var wire bytes.Buffer
	want := AWSRoute{Service: "kms", Region: "us-west-2"}

	require.NoError(t, WriteAWSRoute(&wire, want))
	wire.WriteString("tls-client-hello")

	got, err := ReadAWSRoute(&wire)
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Equal(t, "tls-client-hello", wire.String())
}

func TestReadAWSRouteRejectsInvalidMagic(t *testing.T) {
	_, err := ReadAWSRoute(strings.NewReader("NOPE\x01\x03\x09kmsus-west-2"))

	require.ErrorContains(t, err, "invalid magic")
}

func TestReadAWSRouteRejectsMalformedHeaders(t *testing.T) {
	tests := map[string]struct {
		wire    string
		message string
	}{
		"truncated prefix": {
			wire:    "ARSP",
			message: "read AWS route prefix",
		},
		"unsupported version": {
			wire:    "ARSP\x02\x03\x09kmsus-west-2",
			message: "unsupported AWS route version",
		},
		"empty field": {
			wire:    "ARSP\x01\x00\x09",
			message: "must be non-empty",
		},
		"truncated payload": {
			wire:    "ARSP\x01\x03\x09kmsus-west",
			message: "read AWS route payload",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ReadAWSRoute(strings.NewReader(tc.wire))
			require.ErrorContains(t, err, tc.message)
		})
	}
}

func TestWriteAWSRouteRejectsInvalidFields(t *testing.T) {
	tests := map[string]AWSRoute{
		"empty service":     {Region: "us-west-2"},
		"oversized service": {Service: strings.Repeat("a", 256), Region: "us-west-2"},
		"empty region":      {Service: "kms"},
		"oversized region":  {Service: "kms", Region: strings.Repeat("a", 256)},
	}

	for name, route := range tests {
		t.Run(name, func(t *testing.T) {
			err := WriteAWSRoute(&bytes.Buffer{}, route)
			require.Error(t, err)
		})
	}
}

func TestWriteAWSRoutePropagatesWriterFailure(t *testing.T) {
	err := WriteAWSRoute(errorWriter{err: errors.New("write failed")}, AWSRoute{
		Service: "kms",
		Region:  "us-west-2",
	})

	require.ErrorContains(t, err, "write failed")
}

func TestWriteAWSRouteRejectsShortWrite(t *testing.T) {
	err := WriteAWSRoute(shortWriter{}, AWSRoute{Service: "kms", Region: "us-west-2"})

	require.ErrorIs(t, err, io.ErrShortWrite)
	require.ErrorContains(t, err, "byteproxy: write AWS route")
}

type shortWriter struct{}

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func (shortWriter) Write(p []byte) (int, error) {
	return len(p) - 1, nil
}
