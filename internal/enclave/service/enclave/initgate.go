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
	"sync/atomic"

	"github.com/circlefin/arc-remote-signer/proto/pb"
	"golang.org/x/sync/singleflight"
)

// runInitFunc is the work the gate performs on the first Initialize call.
// Production builds wire the KMS Decrypt path through this callback;
// tests inject failing callbacks to exercise the retry / no-latch path.
// Subsequent concurrent callers observe the same result; on error the gate
// does not latch and the next caller's request runs the work again.
type runInitFunc func(context.Context, *pb.InitializeRequest) error

// initGate is the idempotent convergence primitive mirroring
// gateway-tee-signer's OnceCell + AtomicBool combination. It guarantees:
//
//   - Concurrent Initialize calls collapse onto a single execution of
//     runInit; all callers observe the same outcome.
//   - After a successful run the gate latches; further Initialize calls
//     return nil immediately without re-running runInit.
//   - A failed run does not latch; the next caller re-runs runInit with
//     its own request. (singleflight does not cache errors.)
//
// Implementation note: the atomic.Bool fast-path is checked both outside
// and inside the singleflight callback. The outer check skips the
// singleflight machinery once initialised. The inner check handles the
// narrow race where two callers both pass the outer check before either
// enters the singleflight critical section, so the second one observes
// the latch the first one just set instead of re-running runInit.
type initGate struct {
	sf      singleflight.Group
	done    atomic.Bool
	runInit runInitFunc
}

// newInitGate wires the gate to a runInit callback.
func newInitGate(runInit runInitFunc) *initGate {
	return &initGate{runInit: runInit}
}

// initialized is the fast lock-free check used by signing RPCs to decide
// whether to short-circuit with Unavailable.
func (g *initGate) initialized() bool {
	return g.done.Load()
}

// ensureInitialized runs the gate. Returns nil if the gate is already
// initialised or this call (or a concurrent one) successfully ran runInit.
// Returns the runInit error otherwise; the gate is not latched on error.
func (g *initGate) ensureInitialized(ctx context.Context, req *pb.InitializeRequest) error {
	if g.done.Load() {
		return nil
	}
	// Detach the singleflight leader's runInit from the caller's
	// cancellation signal: only the leader's ctx is captured by the
	// closure, so if the leader's client disconnects every concurrent
	// waiter would otherwise observe context.Canceled even though they
	// themselves are healthy. The leader's deadline (if any) is
	// preserved so a configured Initialize timeout still bounds the
	// work — only the cancellation cause is dropped.
	runCtx, cancel := detachCancel(ctx)
	defer cancel()
	_, err, _ := g.sf.Do("initialize", func() (any, error) {
		if g.done.Load() {
			return nil, nil
		}
		if err := g.runInit(runCtx, req); err != nil {
			return nil, err
		}
		g.done.Store(true)
		return nil, nil
	})
	return err
}

// detachCancel returns a context that inherits parent's values and
// deadline (if any) but is not cancelled when parent is cancelled.
// Used to shield the singleflight leader's runInit from one waiter's
// client disconnect.
//
// Both branches return a CancelFunc so callers can `defer cancel()`
// uniformly: the deadline branch returns the real cancel produced by
// context.WithDeadline; the no-deadline branch returns a no-op cancel
// because the detached context has no resources to release.
func detachCancel(parent context.Context) (context.Context, context.CancelFunc) {
	detached := context.WithoutCancel(parent)
	if dl, ok := parent.Deadline(); ok {
		return context.WithDeadline(detached, dl)
	}
	return detached, func() {
		// No-op: context.WithoutCancel returns a context with no
		// goroutine or done-channel to clean up, so this cancel is
		// only here to keep the function's return signature uniform
		// across both branches.
	}
}
