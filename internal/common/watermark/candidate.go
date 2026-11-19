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

package watermark

import (
	"errors"
	"fmt"

	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
)

// CandidateFromSigningMetadata derives the watermark candidate for a signing
// request. The Boolean result is true when the request needs a watermark.
func CandidateFromSigningMetadata(
	metadata *signerv2.SigningMetadata,
	message []byte,
) (Namespace, Watermark, bool, error) {
	if metadata == nil {
		return "", Watermark{}, false, nil
	}
	if metadata.Kind == signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF ||
		metadata.Kind == signerv2.MessageKind_MESSAGE_KIND_TELEMETRY ||
		metadata.Kind == signerv2.MessageKind_MESSAGE_KIND_DELEGATION {
		if metadata.Height != nil || metadata.Round != nil {
			if metadata.Kind == signerv2.MessageKind_MESSAGE_KIND_VALIDATOR_PROOF {
				return "", Watermark{}, false, errors.New("validator proof must not include height or round")
			}
			if metadata.Kind == signerv2.MessageKind_MESSAGE_KIND_TELEMETRY {
				return "", Watermark{}, false, errors.New("telemetry must not include height or round")
			}
			return "", Watermark{}, false, errors.New("delegation must not include height or round")
		}
		return "", Watermark{}, false, nil
	}
	if metadata.Height == nil || metadata.Round == nil {
		return "", Watermark{}, false, errors.New("watermark metadata requires height and round")
	}

	namespace, rank, err := namespaceAndRank(metadata.Kind)
	if err != nil {
		return "", Watermark{}, false, err
	}
	return namespace, Watermark{
		Tuple: Tuple{
			Height: *metadata.Height,
			Round:  *metadata.Round,
			Rank:   rank,
		},
		MessageHash: HashMessage(message),
	}, true, nil
}

func namespaceAndRank(kind signerv2.MessageKind) (Namespace, Rank, error) {
	switch kind {
	case signerv2.MessageKind_MESSAGE_KIND_PREVOTE:
		return NamespacePrevotes, RankFirst, nil
	case signerv2.MessageKind_MESSAGE_KIND_PRECOMMIT:
		return NamespacePrecommits, RankFirst, nil
	case signerv2.MessageKind_MESSAGE_KIND_PROPOSAL:
		return NamespaceProposals, RankFirst, nil
	case signerv2.MessageKind_MESSAGE_KIND_PROPOSAL_PARTS:
		return NamespaceProposalParts, RankFirst, nil
	default:
		return "", 0, fmt.Errorf("unsupported message kind %d", kind)
	}
}
