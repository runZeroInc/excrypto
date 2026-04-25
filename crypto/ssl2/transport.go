// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/runZeroInc/excrypto/crypto/rsa"
	"github.com/runZeroInc/excrypto/crypto/x509"
)

// HandshakeResult captures the outcome of a successful SSL 2.0 handshake.
type HandshakeResult struct {
	ServerHello *ServerHello
	Certificate *x509.Certificate
	// Cipher is the cipher kind negotiated by the client (i.e. selected
	// from the intersection of CLIENT-HELLO and SERVER-HELLO).
	Cipher CipherKind
}

// pickCipher picks the strongest mutually-supported cipher kind that this
// package can carry encrypted records for.
func pickCipher(offered []CipherKind) (CipherKind, error) {
	preference := []CipherKind{
		CK_DES_192_EDE3_CBC_WITH_MD5,
		CK_RC4_128_WITH_MD5,
		CK_RC2_128_CBC_WITH_MD5,
		CK_DES_64_CBC_WITH_MD5,
		CK_RC4_128_EXPORT40_WITH_MD5,
		CK_RC2_128_CBC_EXPORT40_WITH_MD5,
	}
	off := make(map[CipherKind]bool, len(offered))
	for _, k := range offered {
		off[k] = true
	}
	for _, k := range preference {
		if off[k] && k.IsSupportedForBulk() {
			return k, nil
		}
	}
	return 0, errors.New("ssl2: no mutually-supported cipher kind")
}

// Handshake completes a full SSL 2.0 client handshake on c. It must be
// called after [Conn.Probe] (which performs CLIENT-HELLO ↔ SERVER-HELLO).
// On success the connection is encrypted and ready for [Conn.Read] /
// [Conn.Write].
//
// res is the value returned by Probe. The probe must have observed a
// SERVER-HELLO carrying an X.509 RSA certificate.
func (c *Conn) Handshake(res *ProbeResult) (*HandshakeResult, error) {
	if res == nil || res.ServerHello == nil {
		return nil, errors.New("ssl2: Handshake requires a successful Probe result")
	}
	sh := res.ServerHello
	if sh.CertificateType != CertTypeX509 {
		return nil, fmt.Errorf("ssl2: unsupported certificate type %d", sh.CertificateType)
	}
	if res.Certificate == nil {
		return nil, errors.New("ssl2: Probe did not parse server certificate")
	}
	pub, ok := res.Certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ssl2: server cert public key is %T, want RSA", res.Certificate.PublicKey)
	}
	if res.challenge == nil || res.clientHello == nil {
		return nil, errors.New("ssl2: Probe did not retain handshake state")
	}

	kind, err := pickCipher(sh.CipherSpecs)
	if err != nil {
		return nil, err
	}
	if forced := overrideCipher(); forced != 0 {
		kind = forced
	}
	params, _ := kind.Params()

	// Generate the master key. The first ClearKeyBytes are sent in the
	// clear; the remaining SecretKeyBytes are RSA-encrypted under pub.
	master := make([]byte, params.TotalKeyBytes())
	if _, err := rand.Read(master); err != nil {
		return nil, err
	}
	clearKey := master[:params.ClearKeyBytes]
	secretKey := master[params.ClearKeyBytes:]

	encSecret, err := rsa.EncryptPKCS1v15(rand.Reader, pub, secretKey)
	if err != nil {
		return nil, fmt.Errorf("ssl2: RSA-encrypting master key: %w", err)
	}

	// KEY-ARG / IV for block ciphers.
	var keyArg []byte
	if params.IVBytes > 0 {
		keyArg = make([]byte, params.IVBytes)
		if _, err := rand.Read(keyArg); err != nil {
			return nil, err
		}
	}

	cmk := &ClientMasterKey{
		CipherKind:   kind,
		ClearKey:     clearKey,
		EncryptedKey: encSecret,
		KeyArg:       keyArg,
	}
	wire, err := cmk.Marshal()
	if err != nil {
		return nil, err
	}
	if err := c.WriteRecord(wire); err != nil {
		return nil, fmt.Errorf("ssl2: writing CLIENT-MASTER-KEY: %w", err)
	}

	// Derive symmetric keys.
	clientWriteKey, serverWriteKey, err := deriveKeyMaterial(master, res.challenge, sh.ConnectionID, params.TotalKeyBytes())
	if err != nil {
		return nil, err
	}
	cw, sw := clientWriteKey, serverWriteKey
	_ = cw
	_ = sw
	writeCS, err := newCipherState(kind, clientWriteKey, keyArg)
	if err != nil {
		return nil, err
	}
	readCS, err := newCipherState(kind, serverWriteKey, keyArg)
	if err != nil {
		return nil, err
	}
	// SSL 2.0 sequence numbers count *every* record sent in each direction,
	// including the unencrypted handshake records that preceded encryption.
	// Client has already sent CLIENT-HELLO (seq 0) and CLIENT-MASTER-KEY
	// (seq 1); the next outbound encrypted record (CLIENT-FINISHED) is
	// seq 2. Client has already received SERVER-HELLO (seq 0); the next
	// inbound encrypted record (SERVER-VERIFY) is seq 1.
	writeCS.seq = 2
	readCS.seq = 1
	c.mu.Lock()
	c.read = readCS
	c.write = writeCS
	c.mu.Unlock()

	// Read SERVER-VERIFY (encrypted): payload should be msg_type 5 followed
	// by the original CHALLENGE we sent.
	hdr, body, err := readRecordRaw(c.conn)
	if err != nil {
		return nil, fmt.Errorf("ssl2: reading SERVER-VERIFY: %w", err)
	}
	plain, err := readCS.openRecord(hdr, body)
	if err != nil {
		return nil, fmt.Errorf("ssl2: decrypting SERVER-VERIFY: %w", err)
	}
	sv, err := ParseServerVerify(plain)
	if err != nil {
		return nil, err
	}
	if !equalBytes(sv.Challenge, res.challenge) {
		return nil, errors.New("ssl2: SERVER-VERIFY challenge mismatch")
	}

	// Send CLIENT-FINISHED, encrypted, carrying server's CONNECTION-ID.
	cf := (&ClientFinished{ConnectionID: sh.ConnectionID}).Marshal()
	rec, err := writeCS.sealRecord(cf)
	if err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(rec); err != nil {
		return nil, fmt.Errorf("ssl2: writing CLIENT-FINISHED: %w", err)
	}

	// Read SERVER-FINISHED (encrypted) carrying a fresh session id.
	hdr, body, err = readRecordRaw(c.conn)
	if err != nil {
		return nil, fmt.Errorf("ssl2: reading SERVER-FINISHED: %w", err)
	}
	plain, err = readCS.openRecord(hdr, body)
	if err != nil {
		return nil, fmt.Errorf("ssl2: decrypting SERVER-FINISHED: %w", err)
	}
	if _, err := ParseServerFinished(plain); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.finished = true
	c.mu.Unlock()

	return &HandshakeResult{
		ServerHello: sh,
		Certificate: res.Certificate,
		Cipher:      kind,
	}, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// DialAndHandshake is a convenience wrapper that dials addr, runs Probe, and
// then runs Handshake. It returns the connection (encrypted, ready for I/O)
// and the HandshakeResult.
func DialAndHandshake(addr string, timeout time.Duration) (*Conn, *HandshakeResult, error) {
	dialer := net.Dialer{Timeout: timeout}
	nc, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	c := NewConn(nc)
	if timeout > 0 {
		_ = c.SetDeadline(time.Now().Add(timeout))
	}
	res, err := c.Probe(nil)
	if err != nil {
		_ = nc.Close()
		return nil, nil, err
	}
	if res.PeerError != nil {
		_ = nc.Close()
		return nil, nil, res.PeerError.Code
	}
	hr, err := c.Handshake(res)
	if err != nil {
		_ = nc.Close()
		return nil, nil, err
	}
	if timeout > 0 {
		_ = c.SetDeadline(time.Time{})
	}
	return c, hr, nil
}
