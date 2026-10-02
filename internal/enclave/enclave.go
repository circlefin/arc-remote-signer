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

// Package enclave contains the source code which runs in nitro enclave
package enclave

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/circlefin/arc-remote-signer/internal/common/lifecycle"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awskms"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/awsproxy"
	"github.com/circlefin/arc-remote-signer/internal/enclave/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/enclave/public"
	enclaveSvc "github.com/circlefin/arc-remote-signer/internal/enclave/service/enclave"
)

var (
	_logger     *logging.Logger
	_loggerOnce sync.Once
)

func getLogger() *logging.Logger {
	_loggerOnce.Do(func() {
		_logger = logging.Get("nitro-enclave-signer-enclave")
	})
	return _logger
}

type awsProxyFactory func(*Config) (awsproxy.Provider, error)

func newAWSKMSFactory(cfg *Config, nitroEnabled bool, enclavePvd enclave.Provider) awskms.Factory {
	return func(callCtx context.Context, awsCfg aws.Config, arns []string) (awskms.Provider, error) {
		kmsConfig := &awskms.Config{
			Arns:             arns,
			ConnectTimeout:   cfg.NitroEnclave.KmsConnectTimeoutMs,
			AwsproxyEndpoint: cfg.NitroEnclave.AwsproxyEndpoint,
		}
		if !nitroEnabled {
			return awskms.NewForDevelopment(callCtx, kmsConfig, awsCfg)
		}
		if enclavePvd == nil {
			return nil, fmt.Errorf("cannot use Nitro mode without an enclave provider")
		}
		attestationDocument, err := enclavePvd.AttestKMSRecipient()
		if err != nil {
			return nil, fmt.Errorf("the enclave could not attest the KMS recipient: %w", err)
		}
		return awskms.NewWithAttestation(callCtx, kmsConfig, awsCfg, attestationDocument)
	}
}

func run(cfg *Config, nitroEnabled bool, newAWSProxy awsProxyFactory) error {
	var ctx = context.Background()
	var err error

	if err := validateAwsproxyConfig(cfg); err != nil {
		getLogger().ErrorErr(ctx, "invalid awsproxy configuration", err, nil)
		panic(err)
	}

	getLogger().Info(ctx, "initializing the providers...", nil)
	var enclavePvd enclave.Provider
	if nitroEnabled {
		enclavePvd, err = enclave.New()
		if err != nil {
			panic(err)
		}
	}

	// Initialize enclave services
	getLogger().Info(ctx, "initializing the services...", nil)
	awskmsFactory := newAWSKMSFactory(cfg, nitroEnabled, enclavePvd)
	enclaveService := enclaveSvc.New(
		nitroEnabled,
		enclavePvd,
		awskmsFactory,
		cfg.NitroEnclave.AwsproxyEndpoint,
	)

	// Create server with engine initialization handled in public package
	server, err := public.New(cfg.Public.Server, public.CreateServerParams{
		ServiceName:         cfg.GetName(),
		EnclaveService:      enclaveService,
		NitroEnclaveEnabled: nitroEnabled,
	})
	if err != nil {
		getLogger().ErrorErr(ctx, "failed to create server", err, nil)
		panic(err)
	}

	awsProxy, err := newAWSProxy(cfg)
	if err != nil {
		getLogger().ErrorErr(ctx, "failed to construct awsproxy", err, nil)
		panic(err)
	}

	// lifecycle.Manager shuts down in Manage order, so Manage the server
	// before the proxy: on SIGTERM the server stops first (rejects new
	// RPCs) and the proxy drains last (lets in-flight KMS calls finish).
	lc := lifecycle.NewManager()
	lc.Manage(server)
	lc.Manage(awsProxy)
	lc.Run()
	return nil
}

// validateAwsproxyConfig fails fast when the in-enclave KMS client's dial
// target is misconfigured. It enforces two invariants on
// cfg.NitroEnclave.AwsproxyEndpoint: the host must be loopback (the SDK
// dial is redirected straight to it, so a non-loopback host would route KMS
// traffic off-box), and the port must equal cfg.Awsproxy.BasePort (the port
// the proxy actually binds). The client endpoint and the proxy's base_port
// are configured independently and only align by sharing the same default,
// so a partial override would otherwise surface as an opaque
// connection-refused at Initialize rather than a clear config error.
// (Collapsing these to a single source of truth is tracked as a follow-up.)
func validateAwsproxyConfig(cfg *Config) error {
	u, err := url.Parse(cfg.NitroEnclave.AwsproxyEndpoint)
	if err != nil {
		return fmt.Errorf("parse nitroEnclave.awsproxyEndpoint %q: %w", cfg.NitroEnclave.AwsproxyEndpoint, err)
	}
	// The endpoint host is the literal TCP dial target (awskms.newAwsproxyHTTPClient
	// redirects every SDK dial to it), so it must stay on loopback: the awsproxy
	// listener binds 127.0.0.1 and the in-enclave KMS invariant is that traffic
	// never leaves the box before the proxy bridges it. Reject any other host so a
	// misconfigured endpoint fails loudly at startup rather than silently routing
	// KMS traffic (plaintext, in dev/CI) off-box.
	if host := u.Hostname(); host != "127.0.0.1" && host != "localhost" {
		return fmt.Errorf(
			"nitroEnclave.awsproxyEndpoint %q host %q must be a loopback address (127.0.0.1 or localhost)",
			cfg.NitroEnclave.AwsproxyEndpoint, host)
	}
	port := u.Port()
	if port == "" {
		return fmt.Errorf("nitroEnclave.awsproxyEndpoint %q has no port", cfg.NitroEnclave.AwsproxyEndpoint)
	}
	if want := strconv.FormatUint(uint64(cfg.Awsproxy.BasePort), 10); port != want {
		return fmt.Errorf(
			"config mismatch: nitroEnclave.awsproxyEndpoint port %s must equal awsproxy.base_port %s "+
				"(the in-enclave KMS client dials the endpoint; the awsproxy binds base_port)",
			port, want)
	}
	return nil
}
