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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
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
	"google.golang.org/grpc/test/bufconn"
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
		certPath, keyPath := writeServerKeyPair(t, t.TempDir())
		opts, err := WithTLS(&TLSConfig{Enabled: false, Cert: certPath, Key: keyPath})
		require.NoError(t, err)
		require.Empty(t, opts)
	})

	t.Run("client authentication requires TLS", func(t *testing.T) {
		opts, err := WithTLS(&TLSConfig{
			Enabled: false,
			ClientAuth: ClientAuthConfig{
				Enabled: true,
				CA:      "/unused",
			},
		})
		require.Error(t, err)
		require.Nil(t, opts)
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

	t.Run("client authentication requires CA path", func(t *testing.T) {
		opts, err := WithTLS(&TLSConfig{
			Enabled: true,
			Cert:    "/unused/server-cert.pem",
			Key:     "/unused/server-key.pem",
			ClientAuth: ClientAuthConfig{
				Enabled: true,
			},
		})
		require.Error(t, err)
		require.Nil(t, opts)
	})

	t.Run("client authentication rejects missing CA file", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := writeServerKeyPair(t, dir)
		opts, err := WithTLS(&TLSConfig{
			Enabled: true,
			Cert:    certPath,
			Key:     keyPath,
			ClientAuth: ClientAuthConfig{
				Enabled: true,
				CA:      filepath.Join(dir, "absent-client-ca.pem"),
			},
		})
		require.Error(t, err)
		require.Nil(t, opts)
	})

	t.Run("client authentication rejects malformed CA bundle", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := writeServerKeyPair(t, dir)
		clientCAPath := filepath.Join(dir, "client-ca.pem")
		require.NoError(t, os.WriteFile(clientCAPath, []byte("not a PEM certificate"), 0o600))

		opts, err := WithTLS(&TLSConfig{
			Enabled: true,
			Cert:    certPath,
			Key:     keyPath,
			ClientAuth: ClientAuthConfig{
				Enabled: true,
				CA:      clientCAPath,
			},
		})
		require.Error(t, err)
		require.ErrorContains(t, err, clientCAPath)
		require.Nil(t, opts)
	})

	t.Run("client authentication rejects partially corrupted CA bundle", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := writeServerKeyPair(t, dir)
		clientCAPath, _ := writeCertificateAuthority(t, dir, "client-ca")
		clientCAPEM, err := os.ReadFile(clientCAPath)
		require.NoError(t, err)
		clientCAPEM = append(clientCAPEM, []byte("\ncorrupted trailing content")...)
		require.NoError(t, os.WriteFile(clientCAPath, clientCAPEM, 0o600))

		opts, err := WithTLS(&TLSConfig{
			Enabled: true,
			Cert:    certPath,
			Key:     keyPath,
			ClientAuth: ClientAuthConfig{
				Enabled: true,
				CA:      clientCAPath,
			},
		})
		require.Error(t, err)
		require.ErrorContains(t, err, clientCAPath)
		require.Nil(t, opts)
	})

	t.Run("client authentication requires trusted client certificate", func(t *testing.T) {
		dir := t.TempDir()
		serverCAPath, serverCA := writeCertificateAuthority(t, dir, "server-ca")
		serverCertPath, serverKeyPath := writeSignedKeyPair(
			t,
			dir,
			"server",
			serverCA,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			[]string{"localhost"},
		)
		clientCAPath, clientCA := writeCertificateAuthority(t, dir, "client-ca")
		trustedClientCertPath, trustedClientKeyPath := writeSignedKeyPair(
			t,
			dir,
			"trusted-client",
			clientCA,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			nil,
		)
		_, untrustedClientCA := writeCertificateAuthority(t, dir, "untrusted-client-ca")
		untrustedClientCertPath, untrustedClientKeyPath := writeSignedKeyPair(
			t,
			dir,
			"untrusted-client",
			untrustedClientCA,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			nil,
		)

		opts, err := WithTLS(&TLSConfig{
			Enabled: true,
			Cert:    serverCertPath,
			Key:     serverKeyPath,
			ClientAuth: ClientAuthConfig{
				Enabled: true,
				CA:      clientCAPath,
			},
		})
		require.NoError(t, err)
		listener := startHealthServer(t, opts)

		trustedClientCredentials := newClientTLSCredentials(
			t,
			serverCAPath,
			trustedClientCertPath,
			trustedClientKeyPath,
		)
		require.NoError(t, checkHealth(listener, trustedClientCredentials))

		serverTrustOnlyCredentials := newClientTLSCredentials(t, serverCAPath, "", "")
		require.Error(t, checkHealth(listener, serverTrustOnlyCredentials))

		untrustedClientCredentials := newClientTLSCredentials(
			t,
			serverCAPath,
			untrustedClientCertPath,
			untrustedClientKeyPath,
		)
		require.Error(t, checkHealth(listener, untrustedClientCredentials))
	})

	t.Run("server authenticated TLS accepts client without identity", func(t *testing.T) {
		dir := t.TempDir()
		serverCAPath, serverCA := writeCertificateAuthority(t, dir, "server-ca")
		serverCertPath, serverKeyPath := writeSignedKeyPair(
			t,
			dir,
			"server",
			serverCA,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			[]string{"localhost"},
		)

		opts, err := WithTLS(&TLSConfig{
			Enabled: true,
			Cert:    serverCertPath,
			Key:     serverKeyPath,
		})
		require.NoError(t, err)
		listener := startHealthServer(t, opts)

		clientCredentials := newClientTLSCredentials(t, serverCAPath, "", "")
		require.NoError(t, checkHealth(listener, clientCredentials))

		require.Error(t, checkHealth(listener, insecure.NewCredentials()))
	})

	t.Run("logs the successfully loaded client authentication mode", func(t *testing.T) {
		for _, clientAuthEnabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("enabled=%t", clientAuthEnabled), func(t *testing.T) {
				dir := t.TempDir()
				certPath, keyPath := writeServerKeyPair(t, dir)
				cfg := &TLSConfig{
					Enabled: true,
					Cert:    certPath,
					Key:     keyPath,
				}
				if clientAuthEnabled {
					clientCAPath, _ := writeCertificateAuthority(t, dir, "client-ca")
					cfg.ClientAuth = ClientAuthConfig{
						Enabled: true,
						CA:      clientCAPath,
					}
				}

				var output bytes.Buffer
				originalOutput := log.Writer()
				log.SetOutput(&output)
				t.Cleanup(func() {
					log.SetOutput(originalOutput)
				})

				opts, err := WithTLS(cfg)
				require.NoError(t, err)
				require.NotEmpty(t, opts)
				require.Contains(
					t,
					output.String(),
					fmt.Sprintf("client authentication enabled=%t", clientAuthEnabled),
				)
			})
		}
	})
}

type testCertificateAuthority struct {
	certificate *x509.Certificate
	privateKey  *ecdsa.PrivateKey
}

func writeServerKeyPair(t *testing.T, dir string) (string, string) {
	t.Helper()

	_, certificateAuthority := writeCertificateAuthority(t, dir, "server-ca")
	return writeSignedKeyPair(
		t,
		dir,
		"server",
		certificateAuthority,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]string{"localhost"},
	)
}

func writeCertificateAuthority(
	t *testing.T,
	dir string,
	name string,
) (string, testCertificateAuthority) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	require.NoError(t, err)

	certificatePath := filepath.Join(dir, name+".pem")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	require.NoError(t, os.WriteFile(certificatePath, certificatePEM, 0o600))

	return certificatePath, testCertificateAuthority{
		certificate: template,
		privateKey:  privateKey,
	}
}

func writeSignedKeyPair(
	t *testing.T,
	dir string,
	name string,
	certificateAuthority testCertificateAuthority,
	extendedKeyUsage []x509.ExtKeyUsage,
	dnsNames []string,
) (string, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  extendedKeyUsage,
		DNSNames:     dnsNames,
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		certificateAuthority.certificate,
		&privateKey.PublicKey,
		certificateAuthority.privateKey,
	)
	require.NoError(t, err)

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	certificatePath := filepath.Join(dir, name+"-cert.pem")
	privateKeyPath := filepath.Join(dir, name+"-key.pem")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	require.NoError(t, os.WriteFile(certificatePath, certificatePEM, 0o600))
	require.NoError(t, os.WriteFile(privateKeyPath, privateKeyPEM, 0o600))

	return certificatePath, privateKeyPath
}

func startHealthServer(t *testing.T, opts []grpc.ServerOption) *bufconn.Listener {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(opts...)
	healthServer := grpcHealth.NewServer()
	grpcHealthV1.RegisterHealthServer(server, healthServer)
	healthServer.SetServingStatus("", grpcHealthV1.HealthCheckResponse_SERVING)

	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		if err := listener.Close(); err != nil {
			t.Errorf("failed to close in-memory listener: %v", err)
		}
	})

	return listener
}

func newClientTLSCredentials(
	t *testing.T,
	serverCAPath string,
	clientCertificatePath string,
	clientKeyPath string,
) credentials.TransportCredentials {
	t.Helper()

	serverCAPEM, err := os.ReadFile(serverCAPath)
	require.NoError(t, err)
	serverCAs := x509.NewCertPool()
	require.True(t, serverCAs.AppendCertsFromPEM(serverCAPEM))

	tlsConfig := &tls.Config{
		RootCAs:    serverCAs,
		ServerName: "localhost",
	}
	if clientCertificatePath != "" {
		clientCertificate, err := tls.LoadX509KeyPair(clientCertificatePath, clientKeyPath)
		require.NoError(t, err)
		tlsConfig.Certificates = []tls.Certificate{clientCertificate}
	}

	return credentials.NewTLS(tlsConfig)
}

func checkHealth(
	listener *bufconn.Listener,
	transportCredentials credentials.TransportCredentials,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	connection, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(transportCredentials),
	)
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()

	_, err = grpcHealthV1.NewHealthClient(connection).Check(
		ctx,
		&grpcHealthV1.HealthCheckRequest{},
	)
	return err
}
