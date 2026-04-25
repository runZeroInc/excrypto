// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestServerHandshakeAgainstOwnClient runs the production [Server] against
// the production [Conn.Probe]+[Conn.Handshake] client across every cipher
// kind that supports bulk encryption, in both directions of application
// data.
func TestServerHandshakeAgainstOwnClient(t *testing.T) {
	der, priv := rsaSelfSignedCert(t)
	allCiphers := []CipherKind{
		CK_RC4_128_WITH_MD5,
		CK_RC4_128_EXPORT40_WITH_MD5,
		CK_RC2_128_CBC_WITH_MD5,
		CK_RC2_128_CBC_EXPORT40_WITH_MD5,
		CK_DES_64_CBC_WITH_MD5,
		CK_DES_192_EDE3_CBC_WITH_MD5,
	}
	for _, kind := range allCiphers {
		t.Run(kind.Name(), func(t *testing.T) {
			clientNC, serverNC := net.Pipe()
			defer clientNC.Close()
			defer serverNC.Close()

			cfg := &Config{
				Certificate: der,
				PrivateKey:  priv,
				CipherSpecs: []CipherKind{kind},
			}

			var (
				wg     sync.WaitGroup
				srvRes *ServerHandshakeResult
				srvErr error
			)
			wg.Add(1)
			go func() {
				defer wg.Done()
				s := NewConn(serverNC)
				srvRes, srvErr = s.ServerHandshake(cfg)
				if srvErr != nil {
					return
				}
				// Echo loop: read N bytes, write same back, exit.
				buf := make([]byte, 64)
				n, err := s.Read(buf)
				if err != nil {
					srvErr = err
					return
				}
				if _, err := s.Write(buf[:n]); err != nil {
					srvErr = err
					return
				}
			}()

			c := NewConn(clientNC)
			res, err := c.Probe(nil)
			if err != nil {
				t.Fatalf("client Probe: %v", err)
			}
			hr, err := c.Handshake(res)
			if err != nil {
				t.Fatalf("client Handshake: %v", err)
			}
			if hr.Cipher != kind {
				t.Errorf("client negotiated %s, want %s", hr.Cipher.Name(), kind.Name())
			}

			payload := []byte("ssl2 echo " + kind.Name())
			var clientWg sync.WaitGroup
			clientWg.Add(1)
			go func() {
				defer clientWg.Done()
				if _, werr := c.Write(payload); werr != nil {
					t.Errorf("client Write: %v", werr)
				}
			}()

			echoBuf := make([]byte, len(payload))
			if _, err := io.ReadFull(c, echoBuf); err != nil {
				t.Fatalf("client Read: %v", err)
			}
			if !bytes.Equal(echoBuf, payload) {
				t.Errorf("echo mismatch: got %q, want %q", echoBuf, payload)
			}

			clientWg.Wait()
			wg.Wait()
			if srvErr != nil {
				t.Fatalf("server-side error: %v", srvErr)
			}
			if srvRes == nil || srvRes.Cipher != kind {
				t.Errorf("server result mismatch: %+v", srvRes)
			}
		})
	}
}

// TestServerNoCommonCipher checks that a CLIENT-HELLO offering only ciphers
// the server does not advertise produces a peer ERROR (NO-CIPHER) and a
// non-nil error from ServerHandshake.
func TestServerNoCommonCipher(t *testing.T) {
	der, priv := rsaSelfSignedCert(t)

	clientNC, serverNC := net.Pipe()
	defer clientNC.Close()
	defer serverNC.Close()

	cfg := &Config{
		Certificate: der,
		PrivateKey:  priv,
		CipherSpecs: []CipherKind{CK_DES_192_EDE3_CBC_WITH_MD5},
	}

	var srvErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, srvErr = NewConn(serverNC).ServerHandshake(cfg)
	}()

	// Send a client hello offering only an export RC4 cipher. We use the
	// raw record API rather than Probe so we can control the cipher list.
	c := NewConn(clientNC)
	hello := &ClientHello{
		Version:     Version,
		CipherSpecs: []CipherKind{CK_RC4_128_EXPORT40_WITH_MD5},
		Challenge:   bytes.Repeat([]byte{0x77}, 16),
	}
	wire, err := hello.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WriteRecord(wire); err != nil {
		t.Fatal(err)
	}

	// Server should respond with an SSL 2.0 ERROR (NO-CIPHER) record.
	resp, err := c.ReadRecord()
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	pe, err := ParseError(resp)
	if err != nil {
		t.Fatalf("expected ERROR record; got %x (%v)", resp, err)
	}
	if pe.Code != ErrNoCipher {
		t.Errorf("error code = %s, want NO-CIPHER", pe.Code)
	}

	wg.Wait()
	if srvErr == nil {
		t.Error("server handshake should have errored")
	}
}

// TestServerListener exercises the high-level Server type end-to-end via a
// real TCP loopback listener.
func TestServerListener(t *testing.T) {
	der, priv := rsaSelfSignedCert(t)

	cfg := &Config{Certificate: der, PrivateKey: priv}
	srv := &Server{
		Config:           cfg,
		HandshakeTimeout: 5 * time.Second,
		Handler: func(c *Conn, res *ServerHandshakeResult) {
			defer c.Close()
			buf := make([]byte, 64)
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			_, _ = c.Write(buf[:n])
		},
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()

	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(l) }()

	// Client side: dial + full handshake + small echo round trip.
	c, hr, err := DialAndHandshake(addr, 5*time.Second)
	if err != nil {
		t.Fatalf("DialAndHandshake: %v", err)
	}
	defer c.Close()
	if !hr.Cipher.IsSupportedForBulk() {
		t.Errorf("negotiated unsupported cipher %s", hr.Cipher.Name())
	}

	want := []byte("ping over real tcp\n")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, werr := c.Write(want); werr != nil {
			t.Errorf("client Write: %v", werr)
		}
	}()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("client Read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("echo mismatch: got %q want %q", got, want)
	}
	wg.Wait()

	if err := srv.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Errorf("Serve: %v", err)
	}
}
