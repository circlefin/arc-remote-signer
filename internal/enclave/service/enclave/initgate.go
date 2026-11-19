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

// readyState contains the result of a successful initialization. A generated
// key also stores the fingerprint of its envelope. This fingerprint lets the
// host recover the same Ready state after a host-only restart. The gate does
// not modify the Ready state after it is set. The gate returns a copy of the
// stored response. Callers cannot modify the stored response.
type readyState struct {
	fingerprint                     keySourceFingerprint
	generatedEnvelopeFingerprint    keySourceFingerprint
	hasGeneratedEnvelopeFingerprint bool
	key                             enclaveCrypto.Key
	response                        *pb.InitializeResponse
}

// runInitFunc builds a candidate state. It does not set the Ready state. The
// gate sets the Ready state only after this function succeeds.
type runInitFunc func(context.Context, *pb.InitializeRequest) (*readyState, error)

// initGate controls enclave initialization. It provides these guarantees:
//
//   - It runs only one runInit operation at a time.
//   - A call with the same source gets the stored result.
//   - After the Ready state is set, a call with a different source fails
//     without a new KMS call.
//   - A failed run does not set the Ready state. The next call can retry.
//
// The code checks the atomic pointer outside and inside the singleflight
// callback. The second check finds a Ready state that another call set after
// the first check.
type initGate struct {
	sf         singleflight.Group
	ready      atomic.Pointer[readyState]
	runInit    runInitFunc
	runTimeout time.Duration
}

// newInitGate creates a gate for the specified initialization function.
func newInitGate(runInit runInitFunc) *initGate {
	return &initGate{
		runInit:    runInit,
		runTimeout: defaultInitializationTimeout,
	}
}

// initialized reports whether the gate has a Ready state.
func (g *initGate) initialized() bool {
	return g.ready.Load() != nil
}

func (g *initGate) state() *readyState {
	return g.ready.Load()
}

// ensureInitialized sets one Ready state. A call with the same key source gets
// the stored result. After the Ready state is set, a call with a
// different source fails without another runInit operation.
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
		// The shared operation ignores caller cancellation. The operation uses
		// the service timeout. Each caller stops when its own context ends.
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
