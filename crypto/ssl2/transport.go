// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/runZeroInc/excrypto/crypto"
	"github.com/runZeroInc/excrypto/crypto/rsa"
	"github.com/runZeroInc/excrypto/crypto/x509"
)

// ClientConfig configures optional SSL 2.0 client authentication.
type ClientConfig struct {
	// Certificate is the DER-encoded X.509 certificate to send if the server
	// requests client authentication.
	Certificate []byte

	// PrivateKey is the RSA private key matching Certificate.
	PrivateKey *rsa.PrivateKey
}

// HandshakeResult captures the outcome of a successful SSL 2.0 handshake.
type HandshakeResult struct {
	ServerHello                *ServerHello
	Certificate                *x509.Certificate
	ClientCertificateRequested bool
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
	return c.HandshakeWithConfig(res, nil)
}

// HandshakeWithConfig is like [Conn.Handshake], but it can answer SSL 2.0
// REQUEST-CERTIFICATE messages using cfg.
func (c *Conn) HandshakeWithConfig(res *ProbeResult, cfg *ClientConfig) (*HandshakeResult, error) {
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

	// Record everything we just produced into the handshake log.
	c.mu.Lock()
	log := c.log()
	log.ClientMasterKey = cmk
	log.SelectedCipher = kind
	log.KeyMaterial = &SSLv2KeyMaterial{
		MasterKey:      append([]byte(nil), master...),
		ClearKey:       append([]byte(nil), clearKey...),
		SecretKey:      append([]byte(nil), secretKey...),
		KeyArg:         append([]byte(nil), keyArg...),
		ClientWriteKey: append([]byte(nil), clientWriteKey...),
		ServerWriteKey: append([]byte(nil), serverWriteKey...),
	}
	c.mu.Unlock()
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
	if err := rejectClientCertificateRequest(plain); err != nil {
		return nil, err
	}
	sv, err := ParseServerVerify(plain)
	if err != nil {
		return nil, err
	}
	if !equalBytes(sv.Challenge, res.challenge) {
		return nil, errors.New("ssl2: SERVER-VERIFY challenge mismatch")
	}
	c.mu.Lock()
	c.log().ServerVerify = sv
	c.mu.Unlock()

	// Send CLIENT-FINISHED, encrypted, carrying server's CONNECTION-ID.
	cfMsg := &ClientFinished{ConnectionID: sh.ConnectionID}
	cf := cfMsg.Marshal()
	rec, err := writeCS.sealRecord(cf)
	if err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(rec); err != nil {
		return nil, fmt.Errorf("ssl2: writing CLIENT-FINISHED: %w", err)
	}
	c.mu.Lock()
	c.log().ClientFinished = cfMsg
	c.mu.Unlock()

	// Read phase-2 server messages until SERVER-FINISHED. Servers may request
	// a client certificate after SERVER-VERIFY; the client has already sent
	// CLIENT-FINISHED and must keep listening until the server finishes too.
	clientCertificateRequested := false
	for {
		hdr, body, err = readRecordRaw(c.conn)
		if err != nil {
			return nil, fmt.Errorf("ssl2: reading SERVER-FINISHED: %w", err)
		}
		plain, err = readCS.openRecord(hdr, body)
		if err != nil {
			return nil, fmt.Errorf("ssl2: decrypting server handshake message: %w", err)
		}
		if len(plain) == 0 {
			return nil, errors.New("ssl2: empty encrypted server message")
		}
		switch MessageType(plain[0]) {
		case MsgServerFinished:
			sf, err := ParseServerFinished(plain)
			if err != nil {
				return nil, err
			}
			c.mu.Lock()
			c.log().ServerFinished = sf
			c.mu.Unlock()
			goto finished
		case MsgRequestCertificate:
			clientCertificateRequested = true
			req, err := ParseRequestCertificate(plain)
			if err != nil {
				return nil, err
			}
			c.mu.Lock()
			c.log().RequestCertificate = req
			c.mu.Unlock()
			if err := c.sendClientCertificate(req, cfg, writeCS, kind, master, res.challenge, sh.ConnectionID, sh.Certificate); err != nil {
				return nil, err
			}
		case MsgError:
			peerErr, err := ParseError(plain)
			if err != nil {
				return nil, err
			}
			return nil, peerErr.Code
		default:
			return nil, fmt.Errorf("ssl2: unexpected encrypted server message %s", MessageType(plain[0]))
		}
	}

finished:
	c.mu.Lock()
	c.finished = true
	c.mu.Unlock()

	return &HandshakeResult{
		ServerHello:                sh,
		Certificate:                res.Certificate,
		ClientCertificateRequested: clientCertificateRequested,
		Cipher:                     kind,
	}, nil
}

func rejectClientCertificateRequest(payload []byte) error {
	if len(payload) > 0 && MessageType(payload[0]) == MsgRequestCertificate {
		return ErrNoCertificate
	}
	return nil
}

func (c *Conn) sendClientCertificate(req *RequestCertificate, cfg *ClientConfig, writeCS *cipherState, kind CipherKind, master, challenge, connID, serverCertificate []byte) error {
	if req.AuthType != AuthTypeMD5WithRSAEncryption {
		return c.sendEncryptedError(writeCS, ErrUnsupportedCert)
	}
	if cfg == nil || len(cfg.Certificate) == 0 || cfg.PrivateKey == nil {
		return c.sendEncryptedError(writeCS, ErrNoCertificate)
	}
	digest, err := clientCertificateDigest(kind, master, challenge, connID, req.Challenge, serverCertificate)
	if err != nil {
		return err
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, cfg.PrivateKey, crypto.MD5, digest)
	if err != nil {
		return fmt.Errorf("ssl2: signing client certificate response: %w", err)
	}
	msg := &ClientCertificate{CertificateType: CertTypeX509, Certificate: cfg.Certificate, Response: sig}
	wire, err := msg.Marshal()
	if err != nil {
		return err
	}
	rec, err := writeCS.sealRecord(wire)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(rec)
	if err == nil {
		c.mu.Lock()
		c.log().ClientCertificate = msg
		c.mu.Unlock()
	}
	return err
}

func (c *Conn) sendEncryptedError(writeCS *cipherState, code ErrorCode) error {
	rec, err := writeCS.sealRecord((&ServerError{Code: code}).Marshal())
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(rec); err != nil {
		return err
	}
	return code
}

func clientCertificateDigest(kind CipherKind, master, challenge, connID, certificateChallenge, serverCertificate []byte) ([]byte, error) {
	params, ok := kind.Params()
	if !ok {
		return nil, fmt.Errorf("ssl2: unknown cipher kind %s", kind.Name())
	}
	blocks := (2*params.TotalKeyBytes() + md5.Size - 1) / md5.Size
	keyMaterial, err := deriveKeyMaterialRaw(master, challenge, connID, blocks*md5.Size)
	if err != nil {
		return nil, err
	}
	h := md5.New()
	h.Write(keyMaterial)
	h.Write(certificateChallenge)
	h.Write(serverCertificate)
	return h.Sum(nil), nil
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
	return DialAndHandshakeWithConfig(addr, timeout, nil)
}

// DialAndHandshakeWithConfig is a convenience wrapper that dials addr, runs
// Probe, and then runs HandshakeWithConfig.
func DialAndHandshakeWithConfig(addr string, timeout time.Duration, cfg *ClientConfig) (*Conn, *HandshakeResult, error) {
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
	hr, err := c.HandshakeWithConfig(res, cfg)
	if err != nil {
		_ = nc.Close()
		return nil, nil, err
	}
	if timeout > 0 {
		_ = c.SetDeadline(time.Time{})
	}
	return c, hr, nil
}
