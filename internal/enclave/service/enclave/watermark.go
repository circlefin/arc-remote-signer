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
	"context"
	"errors"

	"github.com/circlefin/arc-remote-signer/internal/common/watermark"
	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Service) enforceWatermark(
	ctx context.Context,
	publicKey []byte,
	message []byte,
	metadata *signerv2.SigningMetadata,
) error {
	namespace, candidate, required, err := watermark.CandidateFromSigningMetadata(metadata, message)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	if !required {
		return nil
	}

	_, err = s.watermarkRepository(publicKey).CompareAndAdvance(ctx, namespace, candidate)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, watermark.ErrInvalidCandidate):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, watermark.ErrWatermarkViolation):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, watermark.ErrWatermarkStale):
		return status.Error(codes.OutOfRange, err.Error())
	default:
		return status.Error(codes.Internal, "failed to enforce watermark")
	}
}

func (s *Service) watermarkRepository(publicKey []byte) *watermark.MemoryRepository {
	s.watermarkMu.Lock()
	defer s.watermarkMu.Unlock()

	if s.watermarks == nil {
		s.watermarks = make(map[string]*watermark.MemoryRepository)
	}
	// Public-key identity prevents a rewrapped envelope for the same validator
	// from creating an independent watermark.
	key := string(publicKey)
	repository := s.watermarks[key]
	if repository == nil {
		repository = watermark.NewMemoryRepository()
		s.watermarks[key] = repository
	}
	return repository
}
