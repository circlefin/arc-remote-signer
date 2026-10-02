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
	"sync/atomic"
	"time"

	enclaveCrypto "github.com/circlefin/arc-remote-signer/internal/enclave/common/crypto"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type keySourceFingerprint [32]byte

const defaultInitializationTimeout = 30 * time.Second

// readyState is published only after the complete key lifecycle succeeds.
type readyState struct {
	fingerprint                     keySourceFingerprint
	generatedEnvelopeFingerprint    keySourceFingerprint
	hasGeneratedEnvelopeFingerprint bool
	key                             enclaveCrypto.Key
	response                        *pb.InitializeResponse
}

// runInitFunc builds a candidate state without publishing it.
type runInitFunc func(context.Context, *pb.InitializeRequest) (*readyState, error)

type initGate struct {
	sf         singleflight.Group
	ready      atomic.Pointer[readyState]
	runInit    runInitFunc
	runTimeout time.Duration
}

// newInitGate creates an initialization gate.
func newInitGate(runInit runInitFunc) *initGate {
	return &initGate{runInit: runInit, runTimeout: defaultInitializationTimeout}
}

// initialized reports whether a complete Ready state was published.
func (g *initGate) initialized() bool {
	return g.ready.Load() != nil
}

func (g *initGate) state() *readyState {
	return g.ready.Load()
}

// ensureInitialized publishes one complete Ready state.
func (g *initGate) ensureInitialized(
	ctx context.Context,
	req *pb.InitializeRequest,
	fingerprint keySourceFingerprint,
) (*pb.InitializeResponse, error) {
	if state := g.ready.Load(); state != nil {
		return responseForFingerprint(state, fingerprint)
	}
	resultCh := g.sf.DoChan("initialize", func() (any, error) {
		if state := g.ready.Load(); state != nil {
			return state, nil
		}
		runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), g.runTimeout)
		defer cancel()
		state, err := g.runInit(runCtx, req)
		if err != nil {
			return nil, err
		}
		if state == nil || state.response == nil {
			return nil, errors.New("initialize returned an empty ready state")
		}
		state.fingerprint = fingerprint
		if envelope := state.response.GetSecretEnvelope(); envelope != nil {
			recoveryFingerprint, err := fingerprintKeySource(&pb.InitializeRequest{
				KeySource: &pb.InitializeRequest_ExistingKey{ExistingKey: envelope},
			})
			if err != nil {
				return nil, err
			}
			state.generatedEnvelopeFingerprint = recoveryFingerprint
			state.hasGeneratedEnvelopeFingerprint = true
		}
		g.ready.Store(state)
		return state, nil
	})

	var result singleflight.Result
	select {
	case result = <-resultCh:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if result.Err != nil {
		return nil, result.Err
	}
	state, ok := result.Val.(*readyState)
	if !ok || state == nil {
		return nil, errors.New("initialize returned an invalid ready state")
	}
	return responseForFingerprint(state, fingerprint)
}

func responseForFingerprint(
	state *readyState,
	fingerprint keySourceFingerprint,
) (*pb.InitializeResponse, error) {
	if state.fingerprint == fingerprint {
		return proto.Clone(state.response).(*pb.InitializeResponse), nil
	}
	if state.hasGeneratedEnvelopeFingerprint && state.generatedEnvelopeFingerprint == fingerprint {
		response := proto.Clone(state.response).(*pb.InitializeResponse)
		response.SecretEnvelope = nil
		return response, nil
	}
	return nil, status.Error(codes.FailedPrecondition, "enclave is already initialized with a different key source")
}
