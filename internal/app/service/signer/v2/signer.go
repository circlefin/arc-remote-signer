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

//go:generate mockgen -source=signer.go -destination=signer_mock.go -package=v2

// Package v2 implements version 2 of the signer service. The service checks
// durable watermarks before it signs messages.
package v2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"buf.build/go/protovalidate"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/internal/common/replica"
	"github.com/circlefin/arc-remote-signer/internal/common/signing"
	"github.com/circlefin/arc-remote-signer/internal/common/watermark"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"github.com/circlefin/arc-remote-signer/proto/pb/signerv2"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	errInvalidCandidate       = "invalid watermark candidate"
	errWatermarkIndeterminate = "watermark result indeterminate; retry the exact same request"
	errWatermarkCorrupt       = "watermark state corrupt; operator action required"
	errWatermarkRepository    = "watermark repository failure"
	errOtherNodeSigned        = "other node signed"
	errSignMessage            = "failed to sign message"
)

var (
	loggerOnce sync.Once
	logger     *logging.Logger
)

func getLogger() *logging.Logger {
	loggerOnce.Do(func() {
		logger = logging.Get("service.signer.v2")
	})
	return logger
}

// BaseSigner provides the version 1 operations that Service uses to get the
// public key and send requests to the enclave.
type BaseSigner interface {
	PublicKey(context.Context, *pb.PublicKeyRequest) (*pb.PublicKeyResponse, error)
	SignEnclave(context.Context, *pb.SignMessageRequest) (*pb.SignMessageResponse, error)
}

// Service signs version 2 requests. It checks the durable watermark when the
// message type requires a watermark.
type Service struct {
	signerv2.UnimplementedSignerServiceServer
	base            BaseSigner
	repository      watermark.OwnedAdvancer
	validator       protovalidate.Validator
	watermarkPermit *semaphore.Weighted
}

// New creates version 2 of the signer service.
func New(base BaseSigner, repository watermark.OwnedAdvancer) (*Service, error) {
	if base == nil {
		return nil, errors.New("base signer service is required")
	}
	if repository == nil {
		return nil, errors.New("watermark repository is required")
	}
	validator, err := protovalidate.New()
	if err != nil {
		return nil, fmt.Errorf("create request validator: %w", err)
	}
	return &Service{
		base:            base,
		repository:      repository,
		validator:       validator,
		watermarkPermit: semaphore.NewWeighted(1),
	}, nil
}

// PublicKey gets the public key and attestation document from version 1. It
// returns these values in a version 2 response.
func (s *Service) PublicKey(
	ctx context.Context,
	_ *signerv2.PublicKeyRequest,
) (*signerv2.PublicKeyResponse, error) {
	response, err := s.base.PublicKey(ctx, &pb.PublicKeyRequest{})
	if err != nil {
		return nil, err
	}
	return &signerv2.PublicKeyResponse{
		PublicKey:           response.PublicKey,
		AttestationDocument: response.AttestationDocument,
	}, nil
}

// Sign checks and updates the durable watermark when the message type requires
// a watermark. Then, Sign sends the request to the enclave.
func (s *Service) Sign(
	ctx context.Context,
	req *signerv2.SignRequest,
) (*signerv2.SignResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, errInvalidCandidate)
	}
	if err := s.validator.Validate(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, errInvalidCandidate)
	}
	if err := signing.ValidateMessage(req.Metadata, req.Message); err != nil {
		return nil, status.Error(codes.InvalidArgument, errInvalidCandidate)
	}

	namespace, candidate, required, err :=
		watermark.CandidateFromSigningMetadata(req.Metadata, req.Message)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, errInvalidCandidate)
	}
	if required {
		if err := candidate.Validate(namespace); err != nil {
			return nil, status.Error(codes.InvalidArgument, errInvalidCandidate)
		}
		owner, ok := replica.FromContext(ctx)
		if !ok {
			var err error
			owner, err = replica.NewID(req.GetReplicaName())
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, errInvalidCandidate)
			}
		}
		if err := s.watermarkPermit.Acquire(ctx, 1); err != nil {
			return nil, status.FromContextError(err).Err()
		}
		defer s.watermarkPermit.Release(1)
		if err := s.enforceDurableWatermark(ctx, namespace, candidate, owner); err != nil {
			return nil, err
		}
	}

	response, err := s.base.SignEnclave(ctx, &pb.SignMessageRequest{
		Message:  req.Message,
		Metadata: req.Metadata,
	})
	if err != nil {
		return nil, enclaveStatusError(ctx, err)
	}
	return &signerv2.SignResponse{Signature: response.Signature}, nil
}

func (s *Service) enforceDurableWatermark(
	ctx context.Context,
	namespace watermark.Namespace,
	candidate watermark.Watermark,
	owner replica.ID,
) error {
	outcome, err := s.repository.CompareAndAdvance(ctx, namespace, candidate, owner)
	if err != nil {
		return watermarkStatusError(ctx, err)
	}
	switch outcome {
	case watermark.OutcomeAdvanced, watermark.OutcomeUnchanged:
		return nil
	default:
		getLogger().Error(
			ctx,
			errWatermarkRepository,
			logging.Entries{"outcome": outcome},
		)
		return status.Error(codes.Internal, errWatermarkRepository)
	}
}

func watermarkStatusError(ctx context.Context, err error) error {
	var code codes.Code
	var message string
	switch {
	case errors.Is(err, watermark.ErrWatermarkCorrupt):
		code = codes.Internal
		message = errWatermarkCorrupt
	case errors.Is(err, watermark.ErrWatermarkViolation):
		code = codes.FailedPrecondition
		message = watermark.ErrWatermarkViolation.Error()
	case errors.Is(err, watermark.ErrWatermarkStale):
		code = codes.OutOfRange
		message = watermark.ErrWatermarkStale.Error()
	case errors.Is(err, watermark.ErrWatermarkOwnerConflict):
		code = codes.Aborted
		message = errOtherNodeSigned
	case errors.Is(err, watermark.ErrWatermarkIndeterminate):
		code = codes.Internal
		message = errWatermarkIndeterminate
	case errors.Is(err, watermark.ErrInvalidCandidate):
		code = codes.InvalidArgument
		message = errInvalidCandidate
	default:
		code = codes.Internal
		message = errWatermarkRepository
	}
	getLogger().ErrorErr(ctx, message, err, nil)
	return status.Error(code, message)
}

func enclaveStatusError(ctx context.Context, err error) error {
	enclaveStatus := status.Convert(err)
	switch {
	case enclaveStatus.Code() == codes.FailedPrecondition &&
		strings.HasPrefix(enclaveStatus.Message(), watermark.ErrWatermarkViolation.Error()):
		return status.Error(codes.FailedPrecondition, watermark.ErrWatermarkViolation.Error())
	case enclaveStatus.Code() == codes.OutOfRange &&
		strings.HasPrefix(enclaveStatus.Message(), watermark.ErrWatermarkStale.Error()):
		return status.Error(codes.OutOfRange, watermark.ErrWatermarkStale.Error())
	default:
		getLogger().ErrorErr(ctx, errSignMessage, err, nil)
		return status.Error(codes.Internal, errSignMessage)
	}
}
