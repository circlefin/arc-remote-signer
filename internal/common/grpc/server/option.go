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

package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/mdlayher/vsock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcHealth "google.golang.org/grpc/health"
	grpcHealthV1 "google.golang.org/grpc/health/grpc_health_v1"
)

// ListenerTransport indicates which transport to use when creating a listener.
type ListenerTransport string

const (
	// ListenerTransportTCP creates a tcp listener using host and port.
	ListenerTransportTCP ListenerTransport = "tcp"
	// ListenerTransportVSOCK creates a vsock listener using port.
	ListenerTransportVSOCK ListenerTransport = "vsock"
)

// RunnableOption customizes RunnableServer behavior.
type RunnableOption func(*RunnableImpl) error

// WithListener creates and configures a listener using the given transport.
func WithListener(transport ListenerTransport, host string, port uint32) RunnableOption {
	return func(r *RunnableImpl) error {
		switch transport {
		case ListenerTransportTCP:
			listener, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
			if err != nil {
				return err
			}
			r.listener = listener
		case ListenerTransportVSOCK:
			listener, err := vsock.Listen(port, &vsock.Config{})
			if err != nil {
				return err
			}
			r.listener = listener
		default:
			return fmt.Errorf("unsupported listener transport: %s", transport)
		}
		return nil
	}
}

// WithHealthServer registers grpc health service and manages serving status lifecycle.
func WithHealthServer(serviceNames ...string) RunnableOption {
	return func(r *RunnableImpl) error {
		healthServer := grpcHealth.NewServer()
		grpcHealthV1.RegisterHealthServer(r.server, healthServer)

		healthServer.SetServingStatus("", grpcHealthV1.HealthCheckResponse_SERVING)
		for _, svc := range serviceNames {
			healthServer.SetServingStatus(svc, grpcHealthV1.HealthCheckResponse_SERVING)
		}

		r.beforeShutdownFns = append(r.beforeShutdownFns, func() {
			healthServer.SetServingStatus("", grpcHealthV1.HealthCheckResponse_NOT_SERVING)
			for _, svc := range serviceNames {
				healthServer.SetServingStatus(svc, grpcHealthV1.HealthCheckResponse_NOT_SERVING)
			}
		})
		return nil
	}
}

// WithTLS creates a TLS server option from the given TLS configuration.
func WithTLS(cfg *TLSConfig) ([]grpc.ServerOption, error) {
	if cfg == nil {
		return []grpc.ServerOption{}, nil
	}
	if !cfg.Enabled {
		if cfg.ClientAuth.Enabled {
			return nil, fmt.Errorf("TLS client authentication requires TLS to be enabled")
		}
		return []grpc.ServerOption{}, nil
	}
	if cfg.Cert == "" || cfg.Key == "" {
		return nil, fmt.Errorf("TLS is enabled but cert/key paths are not configured")
	}
	if cfg.ClientAuth.Enabled && cfg.ClientAuth.CA == "" {
		return nil, fmt.Errorf("TLS client authentication is enabled but CA path is not configured")
	}

	certificate, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}

	if cfg.ClientAuth.Enabled {
		clientCAPEM, err := os.ReadFile(cfg.ClientAuth.CA)
		if err != nil {
			return nil, fmt.Errorf("failed to read TLS client CA: %w", err)
		}
		clientCAs, err := certPoolFromPEM(clientCAPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse TLS client CA %q: %w", cfg.ClientAuth.CA, err)
		}
		tlsConfig.ClientCAs = clientCAs
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	log.Printf(
		"loaded TLS config for gRPC server (client authentication enabled=%t)",
		cfg.ClientAuth.Enabled,
	)
	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))}, nil
}

func certPoolFromPEM(data []byte) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	remaining := bytes.TrimSpace(data)
	certificateCount := 0

	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("bundle contains invalid PEM data")
		}

		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("bundle contains an invalid certificate PEM block")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("bundle contains an invalid certificate: %w", err)
		}

		certPool.AddCert(certificate)
		certificateCount++
		remaining = bytes.TrimSpace(rest)
	}

	if certificateCount == 0 {
		return nil, fmt.Errorf("bundle contains no certificates")
	}
	return certPool, nil
}
