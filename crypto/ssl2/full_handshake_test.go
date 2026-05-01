// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/runZeroInc/excrypto/crypto/rsa"
	"github.com/runZeroInc/excrypto/crypto/x509"
	"github.com/runZeroInc/excrypto/crypto/x509/pkix"
)

// rsaSelfSignedCert returns (DER cert, RSA private key). The cert's
// SubjectPublicKeyInfo is RSA so the SSL 2.0 client can encrypt the master
// key under it.
func rsaSelfSignedCert(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ssl2.fullhandshake.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der, priv
}

func TestFullHandshakeOverNetPipe(t *testing.T) {
	for _, name := range []string{"rc4", "des", "3des", "rc2"} {
		t.Run(name, func(t *testing.T) {
			clientNC, serverNC := net.Pipe()
			defer clientNC.Close()
			defer serverNC.Close()

			der, priv := rsaSelfSignedCert(t)

			// Tweak: restrict server's offered ciphers so client picks the
			// one we are testing.
			var only []CipherKind
			switch name {
			case "rc4":
				only = []CipherKind{CK_RC4_128_WITH_MD5}
			case "des":
				only = []CipherKind{CK_DES_64_CBC_WITH_MD5}
			case "3des":
				only = []CipherKind{CK_DES_192_EDE3_CBC_WITH_MD5}
			case "rc2":
				only = []CipherKind{CK_RC2_128_CBC_WITH_MD5}
			}

			errc := make(chan error, 1)
			srv := NewConn(serverNC)
			go func() {
				errc <- runServerWithCiphers(srv, der, priv, only)
			}()

			c := NewConn(clientNC)
			res, err := c.Probe(nil)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			hr, err := c.Handshake(res)
			if err != nil {
				t.Fatalf("Handshake: %v", err)
			}
			if hr.Cipher != only[0] {
				t.Errorf("negotiated %s, want %s", hr.Cipher.Name(), only[0].Name())
			}

			// HandshakeLog should be populated end-to-end.
			hl := c.GetHandshakeLog()
			if hl == nil {
				t.Fatalf("GetHandshakeLog returned nil")
			}
			if hl.ClientHello == nil || hl.ServerHello == nil ||
				hl.ClientMasterKey == nil || hl.ServerVerify == nil ||
				hl.ClientFinished == nil || hl.ServerFinished == nil {
				t.Errorf("HandshakeLog missing wire messages: %+v", hl)
			}
			if hl.SelectedCipher != only[0] {
				t.Errorf("HandshakeLog.SelectedCipher = %s, want %s", hl.SelectedCipher.Name(), only[0].Name())
			}
			if hl.KeyMaterial == nil ||
				len(hl.KeyMaterial.MasterKey) == 0 ||
				len(hl.KeyMaterial.ClientWriteKey) == 0 ||
				len(hl.KeyMaterial.ServerWriteKey) == 0 {
				t.Errorf("HandshakeLog.KeyMaterial incomplete: %+v", hl.KeyMaterial)
			}

			// Application-data round trip: client → server → client echo.
			payload := []byte("hello over sslv2\n")
			var clientWg sync.WaitGroup
			clientWg.Add(1)
			go func() {
				defer clientWg.Done()
				if _, werr := c.Write(payload); werr != nil {
					t.Errorf("client Write: %v", werr)
				}
			}()

			// Server reads payload, then echoes it back from a goroutine
			// (echo is concurrent with the client's Read below to avoid
			// deadlocking the synchronous net.Pipe).
			rxBuf := make([]byte, len(payload))
			if _, err := io.ReadFull(srv, rxBuf); err != nil {
				t.Fatalf("server Read: %v", err)
			}
			if !bytes.Equal(rxBuf, payload) {
				t.Errorf("server got %q, want %q", rxBuf, payload)
			}
			var srvWg sync.WaitGroup
			srvWg.Add(1)
			go func() {
				defer srvWg.Done()
				if _, werr := srv.Write(rxBuf); werr != nil {
					t.Errorf("server Write: %v", werr)
				}
			}()

			echoBuf := make([]byte, len(payload))
			if _, err := io.ReadFull(c, echoBuf); err != nil {
				t.Fatalf("client Read: %v", err)
			}
			if !bytes.Equal(echoBuf, payload) {
				t.Errorf("client echo got %q, want %q", echoBuf, payload)
			}

			clientWg.Wait()
			srvWg.Wait()
			if err := <-errc; err != nil {
				t.Fatalf("server: %v", err)
			}
		})
	}
}

func TestHandshakeCertificateRequestReturnsBadCertificate(t *testing.T) {
	clientNC, serverNC := net.Pipe()
	defer clientNC.Close()
	defer serverNC.Close()

	der, priv := rsaSelfSignedCert(t)
	errc := make(chan error, 1)
	go func() {
		_, err := NewConn(serverNC).ServerHandshake(&Config{
			Certificate:              der,
			PrivateKey:               priv,
			CipherSpecs:              []CipherKind{CK_RC4_128_WITH_MD5},
			RequireClientCertificate: true,
			CertificateChallengeSource: func() ([]byte, error) {
				return bytes.Repeat([]byte{0x99}, 16), nil
			},
		})
		errc <- err
	}()

	c := NewConn(clientNC)
	res, err := c.Probe(nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	_, err = c.Handshake(res)
	if err == nil {
		t.Fatal("Handshake unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "bad certificate") {
		t.Fatalf("Handshake error = %q, want bad certificate", err)
	}
	serverErr := <-errc
	if serverErr == nil {
		t.Fatal("server handshake unexpectedly succeeded")
	}
	if !strings.Contains(serverErr.Error(), "bad certificate") {
		t.Fatalf("server error = %q, want bad certificate", serverErr)
	}
}

func TestHandshakeWithClientCertificate(t *testing.T) {
	clientNC, serverNC := net.Pipe()
	defer clientNC.Close()
	defer serverNC.Close()

	serverDER, serverKey := rsaSelfSignedCert(t)
	clientDER, clientKey := rsaSelfSignedCert(t)
	errc := make(chan error, 1)
	var srvRes *ServerHandshakeResult
	go func() {
		var err error
		srvRes, err = NewConn(serverNC).ServerHandshake(&Config{
			Certificate:              serverDER,
			PrivateKey:               serverKey,
			CipherSpecs:              []CipherKind{CK_RC4_128_WITH_MD5},
			RequireClientCertificate: true,
			CertificateChallengeSource: func() ([]byte, error) {
				return bytes.Repeat([]byte{0x42}, 16), nil
			},
		})
		errc <- err
	}()

	c := NewConn(clientNC)
	res, err := c.Probe(nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr, err := c.HandshakeWithConfig(res, &ClientConfig{Certificate: clientDER, PrivateKey: clientKey})
	if err != nil {
		t.Fatalf("HandshakeWithConfig: %v", err)
	}
	if !hr.ClientCertificateRequested {
		t.Fatal("ClientCertificateRequested = false, want true")
	}
	if hr.Cipher != CK_RC4_128_WITH_MD5 {
		t.Fatalf("client negotiated %s, want %s", hr.Cipher.Name(), CK_RC4_128_WITH_MD5.Name())
	}
	if err := <-errc; err != nil {
		t.Fatalf("server: %v", err)
	}
	if srvRes == nil || srvRes.ClientCertificate == nil {
		t.Fatal("server did not record client certificate")
	}
	if got := srvRes.ClientCertificate.Subject.CommonName; got != "ssl2.fullhandshake.test" {
		t.Fatalf("client certificate CN = %q", got)
	}
}

func TestNoCertificateErrorContainsBadCertificate(t *testing.T) {
	if got := ErrNoCertificate.Error(); !strings.Contains(got, "bad certificate") {
		t.Fatalf("ErrNoCertificate.Error() = %q, want bad certificate", got)
	}
}

// runServerWithCiphers replicates the inline server but accepts a custom
// cipher list. We factor it out so the table-driven test can vary it.
func runServerWithCiphers(srv *Conn, der []byte, priv *rsa.PrivateKey, ciphers []CipherKind) error {
	ch, err := srv.AcceptClientHello()
	if err != nil {
		return err
	}
	connID := bytes.Repeat([]byte{0xC0}, 16)
	sh := &ServerHello{
		CertificateType: CertTypeX509,
		Version:         Version,
		Certificate:     der,
		CipherSpecs:     ciphers,
		ConnectionID:    connID,
	}
	if err := srv.SendServerHello(sh); err != nil {
		return err
	}
	cmkBytes, err := srv.ReadRecord()
	if err != nil {
		return err
	}
	cmk, err := ParseClientMasterKey(cmkBytes)
	if err != nil {
		return err
	}
	params, ok := cmk.CipherKind.Params()
	if !ok {
		return errors.New("server: unknown cipher kind")
	}
	secret, err := rsa.DecryptPKCS1v15(rand.Reader, priv, cmk.EncryptedKey)
	if err != nil {
		return err
	}
	if len(secret) != params.SecretKeyBytes || len(cmk.ClearKey) != params.ClearKeyBytes {
		return errors.New("server: bad key material lengths")
	}
	master := append(append([]byte{}, cmk.ClearKey...), secret...)
	cw, sw, err := deriveKeyMaterial(master, ch.Challenge, connID, params.TotalKeyBytes())
	if err != nil {
		return err
	}
	read, err := newCipherState(cmk.CipherKind, cw, cmk.KeyArg)
	if err != nil {
		return err
	}
	write, err := newCipherState(cmk.CipherKind, sw, cmk.KeyArg)
	if err != nil {
		return err
	}
	// Server mirror of the client-side seq init in transport.go: server's
	// write_seq starts at 1 (SERVER-HELLO was record 0); read_seq starts
	// at 2 (CLIENT-HELLO=0, CLIENT-MASTER-KEY=1).
	write.seq = 1
	read.seq = 2
	srv.read = read
	srv.write = write
	rec, err := write.sealRecord((&ServerVerify{Challenge: ch.Challenge}).Marshal())
	if err != nil {
		return err
	}
	if _, err := srv.conn.Write(rec); err != nil {
		return err
	}
	hdr, body, err := readRecordRaw(srv.conn)
	if err != nil {
		return err
	}
	plain, err := read.openRecord(hdr, body)
	if err != nil {
		return err
	}
	cf, err := ParseClientFinished(plain)
	if err != nil {
		return err
	}
	if !bytes.Equal(cf.ConnectionID, connID) {
		return errors.New("server: CLIENT-FINISHED connection id mismatch")
	}
	sid := bytes.Repeat([]byte{0xAA}, 16)
	rec, err = write.sealRecord((&ServerFinished{SessionID: sid}).Marshal())
	if err != nil {
		return err
	}
	if _, err := srv.conn.Write(rec); err != nil {
		return err
	}
	return nil
}
