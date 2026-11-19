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

// Package signing validates fixed message formats for signer v2.
package signing

import (
	"bytes"
	"errors"

	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
)

const telemetryDigestSize = 32
const delegationPreimageSize = 130

var (
	telemetryDomain             = []byte("arc/telemetry/v1\x00")
	errInvalidTelemetryMessage  = errors.New("invalid telemetry message")
	delegationPrefix            = []byte("arc/auth/v1\x00")
	delegationDomain            = []byte("arc-boost")
	errInvalidDelegationMessage = errors.New("invalid delegation message")
)

// ValidateMessage validates the message format for the specified kind.
func ValidateMessage(metadata *signerv2.SigningMetadata, message []byte) error {
	switch metadata.GetKind() {
	case signerv2.MessageKind_MESSAGE_KIND_TELEMETRY:
		if len(message) != len(telemetryDomain)+telemetryDigestSize ||
			!bytes.Equal(message[:len(telemetryDomain)], telemetryDomain) {
			return errInvalidTelemetryMessage
		}
	case signerv2.MessageKind_MESSAGE_KIND_DELEGATION:
		domainStart := len(delegationPrefix) + 1
		if len(message) != delegationPreimageSize ||
			!bytes.Equal(message[:len(delegationPrefix)], delegationPrefix) ||
			message[len(delegationPrefix)] != byte(len(delegationDomain)) ||
			!bytes.Equal(message[domainStart:domainStart+len(delegationDomain)], delegationDomain) {
			return errInvalidDelegationMessage
		}
	}
	return nil
}
