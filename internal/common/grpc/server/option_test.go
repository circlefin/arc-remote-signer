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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpcHealth "google.golang.org/grpc/health"
	grpcHealthV1 "google.golang.org/grpc/health/grpc_health_v1"
)

func TestWithListener_TCPSuccess(t *testing.T) {
	r := &RunnableImpl{server: grpc.NewServer()}
	port := freeTCPPort(t)

	err := WithListener(ListenerTransportTCP, "127.0.0.1", port)(r)
	require.NoError(t, err)
	require.NotNil(t, r.listener)
	_ = r.listener.Close()
}

func TestWithListener_TCPPortInUse(t *testing.T) {
	r := &RunnableImpl{server: grpc.NewServer()}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to create occupied listener")
	defer func() { _ = lis.Close() }()

	tcpAddr, ok := lis.Addr().(*net.TCPAddr)
	require.True(t, ok, "failed to cast addr to tcp addr: %T", lis.Addr())

	err = WithListener(ListenerTransportTCP, "127.0.0.1", uint32(tcpAddr.Port))(r)
	require.Error(t, err)
}

func TestWithListener_VSOCKBranch(t *testing.T) {
	r := &RunnableImpl{server: grpc.NewServer()}
	err := WithListener(ListenerTransportVSOCK, "", 5005)(r)

	// This assertion keeps the test portable:
	// environments without VSOCK support should return an error,
	// while supported environments may succeed and provide a listener.
	if err == nil {
		require.NotNil(t, r.listener, "expected either vsock setup error or configured listener")
		_ = r.listener.Close()
	}
}

func TestWithListener_UnsupportedTransport(t *testing.T) {
	r := &RunnableImpl{server: grpc.NewServer()}
	err := WithListener(ListenerTransport("unknown"), "127.0.0.1", 0)(r)
	require.Error(t, err)
}

func TestWithHealthServer_LifecycleStatus(t *testing.T) {
	server := grpc.NewServer()
	r := &RunnableImpl{server: server}

	require.NoError(t, WithHealthServer("test.service")(r))
	require.Len(t, r.beforeShutdownFns, 1)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to create listener")
	defer func() {
		server.Stop()
		_ = lis.Close()
	}()

	go func() { _ = server.Serve(lis) }()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err, "failed to create grpc client")
	defer func() { _ = conn.Close() }()

	client := grpcHealthV1.NewHealthClient(conn)

	waitForStatus(t, client, "", grpcHealthV1.HealthCheckResponse_SERVING)
	waitForStatus(t, client, "test.service", grpcHealthV1.HealthCheckResponse_SERVING)

	r.beforeShutdownFns[0]()

	waitForStatus(t, client, "", grpcHealthV1.HealthCheckResponse_NOT_SERVING)
	waitForStatus(t, client, "test.service", grpcHealthV1.HealthCheckResponse_NOT_SERVING)
}

func waitForStatus(t *testing.T, client grpcHealthV1.HealthClient, service string, want grpcHealthV1.HealthCheckResponse_ServingStatus) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		resp, err := client.Check(ctx, &grpcHealthV1.HealthCheckRequest{Service: service})
		cancel()
		if err == nil && resp.GetStatus() == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.Failf(t, "health status timeout", "health status for service %q did not become %s", service, want.String())
}

func TestWithTLS(t *testing.T) {
	t.Run("nil config returns no options", func(t *testing.T) {
		opts, err := WithTLS(nil)
		require.NoError(t, err)
		require.Empty(t, opts)
	})

	t.Run("disabled config returns no options", func(t *testing.T) {
		certPath, keyPath := writeSelfSignedKeyPair(t, t.TempDir())
		opts, err := WithTLS(&TLSConfig{Enabled: false, Cert: certPath, Key: keyPath})
		require.NoError(t, err)
		require.Empty(t, opts)
	})

	t.Run("enabled with empty cert or key returns error", func(t *testing.T) {
		opts, err := WithTLS(&TLSConfig{Enabled: true, Cert: "", Key: ""})
		require.Error(t, err)
		require.Nil(t, opts)
	})

	t.Run("enabled with missing files returns error", func(t *testing.T) {
		dir := t.TempDir()
		opts, err := WithTLS(&TLSConfig{
			Enabled: true,
			Cert:    filepath.Join(dir, "absent-cert.pem"),
			Key:     filepath.Join(dir, "absent-key.pem"),
		})
		require.Error(t, err)
		require.Nil(t, opts)
	})

	t.Run("enabled with malformed cert returns error", func(t *testing.T) {
		dir := t.TempDir()
		certPath := filepath.Join(dir, "cert.pem")
		keyPath := filepath.Join(dir, "key.pem")
		require.NoError(t, os.WriteFile(certPath, []byte("not a pem certificate"), 0o600))
		require.NoError(t, os.WriteFile(keyPath, []byte("not a pem key"), 0o600))

		opts, err := WithTLS(&TLSConfig{Enabled: true, Cert: certPath, Key: keyPath})
		require.Error(t, err)
		require.Nil(t, opts)
	})

	t.Run("enabled secures the server with a working TLS handshake", func(t *testing.T) {
		certPath, keyPath := writeSelfSignedKeyPair(t, t.TempDir())

		opts, err := WithTLS(&TLSConfig{Enabled: true, Cert: certPath, Key: keyPath})
		require.NoError(t, err)
		require.Len(t, opts, 1)

		server := grpc.NewServer(opts...)
		healthServer := grpcHealth.NewServer()
		grpcHealthV1.RegisterHealthServer(server, healthServer)
		healthServer.SetServingStatus("", grpcHealthV1.HealthCheckResponse_SERVING)

		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err, "failed to create listener")
		go func() { _ = server.Serve(lis) }()
		t.Cleanup(server.Stop)

		// A client trusting the server cert completes the TLS handshake.
		clientCreds, err := credentials.NewClientTLSFromFile(certPath, "localhost")
		require.NoError(t, err)
		conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(clientCreds))
		require.NoError(t, err, "failed to create grpc client")
		t.Cleanup(func() { _ = conn.Close() })

		client := grpcHealthV1.NewHealthClient(conn)
		waitForStatus(t, client, "", grpcHealthV1.HealthCheckResponse_SERVING)

		// A plaintext client cannot talk to the TLS-secured server.
		insecureConn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		t.Cleanup(func() { _ = insecureConn.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_, err = grpcHealthV1.NewHealthClient(insecureConn).Check(ctx, &grpcHealthV1.HealthCheckRequest{})
		require.Error(t, err, "plaintext client must not reach the TLS server")
	})
}

// writeSelfSignedKeyPair generates an ECDSA self-signed certificate valid for
// localhost/127.0.0.1 and writes the PEM-encoded cert and key into dir,
// returning their paths.
func writeSelfSignedKeyPair(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	return certPath, keyPath
}
