// Copyright 2026 The excrypto Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// TestHandshakeLogTLS12 runs an in-memory TLS 1.2 ECDHE_RSA handshake
// and asserts that [Conn.GetHandshakeLog] is populated end-to-end on
// both sides. It also verifies that the log is JSON-marshalable.
func TestHandshakeLogTLS12(t *testing.T) {
	runHandshakeLogTest(t, VersionTLS12)
}

// TestHandshakeLogTLS13 runs an in-memory TLS 1.3 handshake and
// asserts that [Conn.GetHandshakeLog] is populated end-to-end.
func TestHandshakeLogTLS13(t *testing.T) {
	runHandshakeLogTest(t, VersionTLS13)
}

func runHandshakeLogTest(t *testing.T, version uint16) {
	t.Helper()

	cert := Certificate{
		Certificate: [][]byte{testRSA2048Certificate},
		PrivateKey:  testRSA2048PrivateKey,
	}
	if version == VersionTLS12 {
		// 512-bit key works for TLS 1.2 RSA-PKCS1v15 / ECDHE-RSA-SHA256.
		var err error
		cert, err = X509KeyPair([]byte(rsaCertPEM), []byte(rsaKeyPEM))
		if err != nil {
			t.Fatalf("X509KeyPair: %v", err)
		}
	}

	serverCfg := &Config{
		Certificates: []Certificate{cert},
		MinVersion:   version,
		MaxVersion:   version,
		Rand:         rand.Reader,
		Time:         time.Now,
	}
	clientCfg := &Config{
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
		Rand:               rand.Reader,
		Time:               time.Now,
	}

	clientNC, srvNC := net.Pipe()
	defer clientNC.Close()
	defer srvNC.Close()

	server := Server(srvNC, serverCfg)
	client := Client(clientNC, clientCfg)

	var wg sync.WaitGroup
	wg.Add(1)
	var srvErr error
	go func() {
		defer wg.Done()
		srvErr = server.HandshakeContext(context.Background())
	}()

	if err := client.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	wg.Wait()
	if srvErr != nil {
		t.Fatalf("server handshake: %v", srvErr)
	}

	for label, c := range map[string]*Conn{"client": client, "server": server} {
		log := c.GetHandshakeLog()
		if log == nil {
			t.Fatalf("%s: GetHandshakeLog returned nil", label)
		}
		if log.ClientHello == nil {
			t.Errorf("%s: HandshakeLog.ClientHello is nil", label)
		}
		if log.ServerHello == nil {
			t.Errorf("%s: HandshakeLog.ServerHello is nil", label)
		}
		if log.ServerCertificates == nil {
			t.Errorf("%s: HandshakeLog.ServerCertificates is nil", label)
		}
		if label == "client" && log.ServerCertificates != nil {
			if log.ServerCertificates.Certificate.Parsed == nil {
				t.Errorf("client: ServerCertificates.Certificate.Parsed is nil")
			}
			if log.ServerCertificates.Validation == nil {
				t.Errorf("client: ServerCertificates.Validation is nil (expected non-nil from ValidateWithStupidDetail)")
			}
		}
		if log.ServerFinished == nil {
			t.Errorf("%s: HandshakeLog.ServerFinished is nil", label)
		}
		if log.ClientFinished == nil {
			t.Errorf("%s: HandshakeLog.ClientFinished is nil", label)
		}
		if version == VersionTLS13 {
			if log.EncryptedExtensions == nil {
				t.Errorf("%s: TLS 1.3 HandshakeLog.EncryptedExtensions is nil", label)
			}
		}
		if version == VersionTLS12 {
			// TLS 1.2 with ECDHE_RSA: SKX, CKX, KeyMaterial all populated.
			if log.ServerKeyExchange == nil {
				t.Errorf("%s: TLS 1.2 HandshakeLog.ServerKeyExchange is nil", label)
			}
			if log.ClientKeyExchange == nil {
				t.Errorf("%s: TLS 1.2 HandshakeLog.ClientKeyExchange is nil", label)
			}
			if log.KeyMaterial == nil ||
				log.KeyMaterial.MasterSecret == nil ||
				log.KeyMaterial.PreMasterSecret == nil {
				t.Errorf("%s: TLS 1.2 HandshakeLog.KeyMaterial incomplete: %+v", label, log.KeyMaterial)
			}
		}
		// Roundtrip JSON.
		if _, err := json.Marshal(log); err != nil {
			t.Errorf("%s: json.Marshal(HandshakeLog): %v", label, err)
		}
	}

	if !errors.Is(srvErr, nil) {
		t.Fatalf("server handshake error: %v", srvErr)
	}
}

// TestClientHelloInfoHandshakeLog verifies that GetCertificate / GetConfigForClient
// callbacks can observe the in-progress handshake log via ClientHelloInfo.HandshakeLog.
func TestClientHelloInfoHandshakeLog(t *testing.T) {
	cert, err := X509KeyPair([]byte(rsaCertPEM), []byte(rsaKeyPEM))
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	var seenLog *ServerHandshake
	serverCfg := &Config{
		MinVersion: VersionTLS12,
		MaxVersion: VersionTLS12,
		GetCertificate: func(chi *ClientHelloInfo) (*Certificate, error) {
			seenLog = chi.HandshakeLog
			return &cert, nil
		},
	}
	clientCfg := &Config{
		InsecureSkipVerify: true,
		MinVersion:         VersionTLS12,
		MaxVersion:         VersionTLS12,
		ServerName:         "example.com",
	}

	clientNC, srvNC := net.Pipe()
	defer clientNC.Close()
	defer srvNC.Close()

	server := Server(srvNC, serverCfg)
	client := Client(clientNC, clientCfg)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = server.HandshakeContext(context.Background())
	}()
	if err := client.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	wg.Wait()

	if seenLog == nil {
		t.Fatalf("ClientHelloInfo.HandshakeLog was nil in GetCertificate callback")
	}
	if seenLog.ClientHello == nil {
		t.Errorf("HandshakeLog.ClientHello not populated when GetCertificate fired")
	}
}
