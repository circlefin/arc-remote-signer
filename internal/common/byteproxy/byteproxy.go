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

// Package byteproxy provides a small framework for spawning per-service
// listeners that bidirectionally bridge each accepted connection to an
// upstream dialed by the caller. The accept loop, per-connection bridge,
// bounded concurrency, and shutdown semantics live here so that
// transport-specific wrappers only declare how to bind and how to dial.
package byteproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/circlefin/arc-remote-signer/internal/common/lifecycle"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
)

// ListenFunc returns the inbound listener for one service slot.
type ListenFunc func() (net.Listener, error)

// DialFunc opens an upstream connection for one bridged session. inbound is
// the accepted connection and may be read before bridging to consume routing
// metadata owned by this hop. Bytes read from inbound are consumed and are not
// copied upstream, so intermediate hops must leave downstream metadata unread.
// The ctx is cancelled when the proxy starts shutting down; transports that
// can be cancelled mid-dial (e.g. net.Dialer.DialContext) MUST honor it so a
// hung upstream does not pin Shutdown past its deadline. Transports whose Dial
// cannot accept a ctx (e.g. mdlayher/vsock at v1.2.1) SHOULD race the dial
// against ctx.Done() in the wrapper and close any resulting conn if ctx wins.
type DialFunc func(ctx context.Context, inbound net.Conn) (net.Conn, error)

// ServiceConfig describes one bridge slot.
type ServiceConfig struct {
	// Name is informational; used as a log field.
	Name string

	// Endpoint is informational; logged on dial failure so operators can
	// distinguish endpoint misconfiguration from transport failures. The
	// framework does not consume it for routing — Dial alone produces the
	// upstream connection.
	Endpoint string

	// Listen returns the inbound listener.
	Listen ListenFunc

	// Dial opens the upstream connection for each accepted session.
	Dial DialFunc
}

// Config configures a multi-service proxy.
type Config struct {
	// Name is the identifier returned by lifecycle.Runnable.Name and used
	// as the base for the logger namespace.
	Name string

	// Services declares one slot per service. Order is informational.
	Services []ServiceConfig

	// MaxConns caps in-flight bridged connections per service. Must be > 0.
	MaxConns int
}

// Proxy is the lifecycle.Runnable returned by New. The extra DroppedCount
// method is exposed for observability hooks and tests; consumers that only
// want lifecycle semantics can assign to a lifecycle.Runnable.
//
// Lifecycle contract: Run must complete before Shutdown is invoked, and
// Run is called at most once. lifecycle.Manager satisfies this by calling
// Run synchronously for all runnables before waiting on signals, then
// calling Shutdown sequentially. Direct callers must follow the same
// ordering; interleaving Run and Shutdown from separate goroutines is
// undefined.
type Proxy interface {
	lifecycle.Runnable

	// DroppedCount returns the cumulative number of inbound connections
	// dropped for `service` because its per-service concurrency cap was
	// already at MaxConns. Returns 0 for unknown service names.
	DroppedCount(service string) int64
}

// proxy holds one listener per service and supervises their accept loops.
type proxy struct {
	name      string
	logger    *logging.Logger
	listeners []*serviceListener
	wg        sync.WaitGroup

	// shutdownCh is closed first in Shutdown to gate acceptLoop's post-Accept
	// check before any kernel-queued conn is dispatched.
	shutdownCh chan struct{}
	shutOnce   sync.Once

	// dialCtx is handed to every DialFunc invocation; dialCancel is fired by
	// Shutdown so transports that honor ctx (e.g. net.Dialer.DialContext) and
	// wrappers that race vsock.Dial against ctx.Done() can abort in-flight
	// dials instead of holding the WaitGroup open past Shutdown's deadline.
	dialCtx    context.Context
	dialCancel context.CancelFunc
}

type serviceListener struct {
	ServiceConfig
	ln      net.Listener
	sem     chan struct{}
	dropped atomic.Int64
}

// New creates a multi-service byte proxy. The caller is responsible for
// gating the call on platform availability (vsock requires Linux); New does
// not inspect runtime capabilities.
func New(cfg *Config) (Proxy, error) {
	if cfg == nil {
		return nil, errors.New("byteproxy: nil config")
	}
	if cfg.Name == "" {
		return nil, errors.New("byteproxy: Name must be set")
	}
	if len(cfg.Services) == 0 {
		return nil, errors.New("byteproxy: at least one service required")
	}
	if cfg.MaxConns <= 0 {
		return nil, errors.New("byteproxy: MaxConns must be > 0")
	}

	dialCtx, dialCancel := context.WithCancel(context.Background())
	p := &proxy{
		name:       cfg.Name,
		logger:     logging.Get(cfg.Name + ".byteproxy"),
		shutdownCh: make(chan struct{}),
		dialCtx:    dialCtx,
		dialCancel: dialCancel,
	}

	for _, svc := range cfg.Services {
		if svc.Listen == nil || svc.Dial == nil {
			p.closeListeners()
			dialCancel()
			return nil, fmt.Errorf("byteproxy: service %q missing Listen or Dial", svc.Name)
		}
		ln, err := svc.Listen()
		if err != nil {
			p.closeListeners()
			dialCancel()
			return nil, fmt.Errorf("byteproxy: bind for service %s: %w", svc.Name, err)
		}
		p.listeners = append(p.listeners, &serviceListener{
			ServiceConfig: svc,
			ln:            ln,
			sem:           make(chan struct{}, cfg.MaxConns),
		})
	}
	return p, nil
}

// closeListeners closes every listener currently held by p. Used both by
// New to roll back partially-bound listeners on a construction error, and
// by Shutdown to tear down once the lifecycle ends.
//
// Caller is responsible for any ordering against shutdownCh; this method
// does not signal shutdown on its own.
func (p *proxy) closeListeners() {
	for _, sl := range p.listeners {
		_ = sl.ln.Close()
	}
}

// Name implements lifecycle.Runnable.
func (p *proxy) Name() string { return p.name }

// Run spawns accept loops in background goroutines and returns immediately.
// This matches the lifecycle.Runnable contract used by other services in
// this repo (gRPC server, metrics server) where lifecycle.Manager calls Run
// synchronously and the actual serving runs in a goroutine. Callers wait
// for full drain via Shutdown.
//
// Run is not safe to call concurrently with Shutdown; see the Proxy
// interface godoc for the required ordering.
func (p *proxy) Run() error {
	for _, sl := range p.listeners {
		p.wg.Add(1)
		go p.acceptLoop(context.Background(), sl)
	}
	return nil
}

// Shutdown closes listeners, cancels in-flight dials, and waits for bridge
// goroutines to drain. If ctx expires first, Shutdown returns ctx.Err() —
// bridge goroutines whose DialFunc ignores ctx will outlive this call.
// Idempotent; must not run concurrently with Run.
func (p *proxy) Shutdown(ctx context.Context) error {
	p.shutOnce.Do(func() {
		// Close shutdownCh first so acceptLoop's post-Accept gate observes
		// the signal before any kernel-queued conn slips through. The
		// listener close below races against in-flight Accept calls; both
		// shutdown checks in acceptLoop depend on this ordering.
		close(p.shutdownCh)
		p.closeListeners()
		// Cancel the dial context so in-flight DialFunc calls can abort.
		// Bridge goroutines that have already moved past Dial are unblocked
		// by the listener close above; this signal is for the dial gap.
		p.dialCancel()
	})

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("byteproxy %s: shutdown deadline reached before all goroutines drained: %w", p.name, ctx.Err())
	}
}

// DroppedCount returns the cumulative drop count for the named service.
func (p *proxy) DroppedCount(service string) int64 {
	for _, sl := range p.listeners {
		if sl.Name == service {
			return sl.dropped.Load()
		}
	}
	return 0
}

func (p *proxy) acceptLoop(ctx context.Context, sl *serviceListener) {
	defer p.wg.Done()
	p.logger.Info(ctx, "listener started", logging.Entries{
		"service":  sl.Name,
		"endpoint": sl.Endpoint,
	})

	for {
		conn, err := sl.ln.Accept()
		if err != nil {
			// First shutdown check: Accept returned an error because
			// Shutdown closed the listener. Exit silently.
			select {
			case <-p.shutdownCh:
				return
			default:
			}
			// Accept failures outside shutdown are terminal for this
			// service loop — the listener will no longer accept new
			// connections until the process restarts. Log at error level so
			// the condition surfaces in alerting; transient-error retry
			// can be revisited once CCHAIN-2027 brings a real consumer
			// and we have observability on actual accept failure modes.
			p.logger.ErrorErr(ctx, "accept failed (service loop exiting)", err, logging.Entries{
				"service": sl.Name,
			})
			return
		}

		// Second shutdown check: Accept returned a real conn but Shutdown
		// has already fired (close(shutdownCh) happens before listener
		// Close in Shutdown, so this catches conns that were queued in the
		// kernel backlog at the moment Shutdown started).
		select {
		case <-p.shutdownCh:
			_ = conn.Close()
			return
		default:
		}

		select {
		case sl.sem <- struct{}{}:
		default:
			count := sl.dropped.Add(1)
			p.logger.Warn(ctx, "dropping connection: too many in-flight", logging.Entries{
				"service":       sl.Name,
				"dropped_total": count,
			})
			_ = conn.Close()
			continue
		}

		// Safe to wg.Add here: acceptLoop itself holds a wg ticket
		// (defer p.wg.Done above), so the counter is ≥ 1 throughout and
		// Add-while-positive is always legal per sync.WaitGroup docs.
		p.wg.Add(1)
		go func(c net.Conn) {
			defer p.wg.Done()
			defer func() {
				<-sl.sem
				_ = c.Close()
			}()
			p.bridge(ctx, sl, c)
		}(conn)
	}
}

// bridge dials the upstream for sl and bidirectionally copies bytes between
// inbound and upstream until either side closes or shutdown is signalled.
// The dial uses p.dialCtx so Shutdown can abort dialers that are still
// waiting on the upstream — see the DialFunc godoc for the wrapper contract.
func (p *proxy) bridge(ctx context.Context, sl *serviceListener, inbound net.Conn) {
	upstream, err := sl.Dial(p.dialCtx, inbound)
	if err != nil {
		p.logger.WarnErr(ctx, "upstream dial failed", err, logging.Entries{
			"service":  sl.Name,
			"endpoint": sl.Endpoint,
		})
		return
	}
	defer func() { _ = upstream.Close() }()

	p.pipe(ctx, sl, inbound, upstream)
}

// pipe runs two io.Copy goroutines and returns when both copies have
// exited, either naturally (one side hits EOF, its close cascades to the
// other) or because shutdown was signalled (forcing both sides closed).
// The function always waits for the io.Copy goroutines to finish before
// returning, so it never leaks them past pipe's lifetime.
//
// Non-nil io.Copy errors are logged at Debug level with the direction
// (inbound->upstream or upstream->inbound) so mid-stream resets or write
// failures are diagnosable on demand without flooding production logs.
// io.Copy normalises EOF to nil, and the shutdown path closes both sides
// so a clean shutdown surfaces as net.ErrClosed at Debug too — acceptable
// since the level is off by default in prod.
//
// Close may be called multiple times across the bridge stack (here in pipe,
// in the goroutines' own deferred close-other-side, in bridge's defer, and
// in acceptLoop's outer defer). All callers discard the error and our
// supported transports (TCP, vsock) are idempotent on Close. A future
// transport that panics on double Close would need this assumption revisited.
func (p *proxy) pipe(ctx context.Context, sl *serviceListener, inbound, upstream net.Conn) {
	copyDone := make(chan struct{}, 2)
	go func() {
		_, err := io.Copy(upstream, inbound)
		if err != nil {
			p.logger.DebugErr(ctx, "copy failed", err, logging.Entries{
				"service":   sl.Name,
				"direction": "inbound->upstream",
			})
		}
		_ = upstream.Close()
		copyDone <- struct{}{}
	}()
	go func() {
		_, err := io.Copy(inbound, upstream)
		if err != nil {
			p.logger.DebugErr(ctx, "copy failed", err, logging.Entries{
				"service":   sl.Name,
				"direction": "upstream->inbound",
			})
		}
		_ = inbound.Close()
		copyDone <- struct{}{}
	}()

	shutdown := p.shutdownCh
	finished := 0
	for finished < 2 {
		select {
		case <-copyDone:
			finished++
		case <-shutdown:
			// Force both sides closed so the io.Copy goroutines unblock,
			// then fall through to drain copyDone. Nil out shutdown so we
			// only do this once even if it stays closed.
			_ = inbound.Close()
			_ = upstream.Close()
			shutdown = nil
		}
	}
}
