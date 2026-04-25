// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/runZeroInc/excrypto/crypto/ecdsa"
	"github.com/runZeroInc/excrypto/crypto/elliptic"
	"github.com/runZeroInc/excrypto/crypto/x509"
	"github.com/runZeroInc/excrypto/crypto/x509/pkix"
)

// helperSelfSignedCert returns a DER-encoded self-signed cert. We deliberately
// use ECDSA (not RSA) to avoid pulling in any RSA test fixtures and to keep
// the cert small.
func helperSelfSignedCert(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ssl2.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func TestProbeRoundTripOverNetPipe(t *testing.T) {
	clientNC, serverNC := net.Pipe()
	defer clientNC.Close()
	defer serverNC.Close()

	cert := helperSelfSignedCert(t)
	connID := bytes.Repeat([]byte{0x99}, 16)

	var (
		wg     sync.WaitGroup
		gotCH  *ClientHello
		srvErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		s := NewConn(serverNC)
		ch, err := s.AcceptClientHello()
		if err != nil {
			srvErr = err
			return
		}
		gotCH = ch
		srvErr = s.SendServerHello(&ServerHello{
			SessionIDHit:    false,
			CertificateType: CertTypeX509,
			Version:         Version,
			Certificate:     cert,
			CipherSpecs:     []CipherKind{CK_RC4_128_WITH_MD5, CK_DES_192_EDE3_CBC_WITH_MD5},
			ConnectionID:    connID,
		})
	}()

	c := NewConn(clientNC)
	res, err := c.Probe(nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	wg.Wait()
	if srvErr != nil {
		t.Fatalf("server-side: %v", srvErr)
	}

	if !res.SupportsSSL2() {
		t.Fatal("expected SupportsSSL2() = true")
	}
	if res.PeerError != nil {
		t.Fatalf("unexpected PeerError: %v", res.PeerError.Code)
	}
	if res.ServerHello.CertificateType != CertTypeX509 {
		t.Errorf("cert type = %d", res.ServerHello.CertificateType)
	}
	if res.Certificate == nil {
		t.Fatalf("expected parsed certificate; parse err = %v", res.CertificateParseError)
	}
	if res.Certificate.Subject.CommonName != "ssl2.test" {
		t.Errorf("unexpected CN: %q", res.Certificate.Subject.CommonName)
	}
	if !bytes.Equal(res.ServerHello.ConnectionID, connID) {
		t.Errorf("conn id mismatch")
	}
	wantOffer := AllKnownCipherKinds()
	if len(gotCH.CipherSpecs) != len(wantOffer) {
		t.Errorf("server saw %d ciphers, expected %d", len(gotCH.CipherSpecs), len(wantOffer))
	}
	if len(gotCH.Challenge) != 16 {
		t.Errorf("challenge len = %d", len(gotCH.Challenge))
	}
	got := res.CipherKinds()
	if len(got) != 2 {
		t.Errorf("res.CipherKinds() = %d, want 2", len(got))
	}
}

func TestProbeWithExplicitChallenge(t *testing.T) {
	clientNC, serverNC := net.Pipe()
	defer clientNC.Close()
	defer serverNC.Close()

	want := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 4) // 16 bytes

	var srvCh *ClientHello
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s := NewConn(serverNC)
		ch, _ := s.AcceptClientHello()
		srvCh = ch
		_ = s.SendServerHello(&ServerHello{
			CertificateType: CertTypeX509,
			Version:         Version,
			CipherSpecs:     []CipherKind{CK_RC4_128_WITH_MD5},
			ConnectionID:    bytes.Repeat([]byte{0x01}, 16),
		})
	}()

	c := NewConn(clientNC)
	if _, err := c.Probe(want); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	wg.Wait()
	if !bytes.Equal(srvCh.Challenge, want) {
		t.Errorf("challenge mismatch: got %x", srvCh.Challenge)
	}
}

func TestProbeServerError(t *testing.T) {
	clientNC, serverNC := net.Pipe()
	defer clientNC.Close()
	defer serverNC.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s := NewConn(serverNC)
		_, _ = s.AcceptClientHello()
		_ = s.SendError(ErrNoCipher)
	}()

	c := NewConn(clientNC)
	res, err := c.Probe(nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	wg.Wait()
	if res.SupportsSSL2() {
		t.Errorf("SupportsSSL2() = true, want false on ERROR")
	}
	if res.PeerError == nil || res.PeerError.Code != ErrNoCipher {
		t.Errorf("PeerError = %+v", res.PeerError)
	}
}

func TestProbeUnexpectedMessage(t *testing.T) {
	clientNC, serverNC := net.Pipe()
	defer clientNC.Close()
	defer serverNC.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s := NewConn(serverNC)
		_, _ = s.AcceptClientHello()
		// Send a CLIENT-FINISHED, which the client should never accept here.
		_ = s.WriteRecord((&ClientFinished{ConnectionID: bytes.Repeat([]byte{1}, 16)}).Marshal())
	}()

	c := NewConn(clientNC)
	if _, err := c.Probe(nil); err == nil {
		t.Error("expected error for unexpected initial message")
	}
	wg.Wait()
}

func TestProbeBadCertificate(t *testing.T) {
	clientNC, serverNC := net.Pipe()
	defer clientNC.Close()
	defer serverNC.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s := NewConn(serverNC)
		_, _ = s.AcceptClientHello()
		_ = s.SendServerHello(&ServerHello{
			CertificateType: CertTypeX509,
			Version:         Version,
			Certificate:     []byte{0x00, 0x00, 0x00, 0x00}, // invalid DER
			CipherSpecs:     []CipherKind{CK_RC4_128_WITH_MD5},
			ConnectionID:    bytes.Repeat([]byte{0x01}, 16),
		})
	}()

	c := NewConn(clientNC)
	res, err := c.Probe(nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	wg.Wait()
	if !res.SupportsSSL2() {
		t.Fatal("server returned SERVER-HELLO; SupportsSSL2 should be true")
	}
	if res.Certificate != nil {
		t.Error("expected Certificate=nil for bad DER")
	}
	if res.CertificateParseError == nil {
		t.Error("expected CertificateParseError to be set")
	}
}

func TestProbeNilResultHelpers(t *testing.T) {
	var nilRes *ProbeResult
	if nilRes.SupportsSSL2() {
		t.Error("nil ProbeResult must not report SSL2 support")
	}
	if nilRes.CipherKinds() != nil {
		t.Error("nil ProbeResult must return nil CipherKinds")
	}
}
