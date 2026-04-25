// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/runZeroInc/excrypto/crypto/rsa"
)

// Config configures an SSL 2.0 [Server]. The zero value is not useful;
// callers must populate Certificate and PrivateKey (which together must
// form a working RSA key pair — SSL 2.0 has no other key-exchange option).
type Config struct {
	// Certificate is the DER-encoded X.509 certificate the server will
	// present in its SERVER-HELLO. The SubjectPublicKeyInfo MUST be RSA.
	Certificate []byte

	// PrivateKey is the RSA private key matching Certificate. The server
	// uses it to decrypt the client's SECRET-KEY-DATA from
	// CLIENT-MASTER-KEY.
	PrivateKey *rsa.PrivateKey

	// CipherSpecs is the list of cipher kinds advertised in SERVER-HELLO,
	// in preference order. If empty, [DefaultServerCipherSpecs] is used.
	// The server will negotiate the strongest entry that also appears in
	// the client's CLIENT-HELLO and that this package supports for bulk
	// encryption.
	CipherSpecs []CipherKind

	// SessionIDSource, if non-nil, is called to generate the server's
	// fresh SERVER-FINISHED session id. The default is 16 bytes from
	// crypto/rand.
	SessionIDSource func() ([]byte, error)

	// ConnectionIDSource, if non-nil, is called to generate the server's
	// CONNECTION-ID. The default is 16 bytes from crypto/rand.
	ConnectionIDSource func() ([]byte, error)
}

// DefaultServerCipherSpecs is the default SERVER-HELLO cipher list:
// every cipher kind this package can drive bulk encryption with, ordered
// strongest first.
func DefaultServerCipherSpecs() []CipherKind {
	return []CipherKind{
		CK_DES_192_EDE3_CBC_WITH_MD5,
		CK_RC4_128_WITH_MD5,
		CK_RC2_128_CBC_WITH_MD5,
		CK_DES_64_CBC_WITH_MD5,
		CK_RC4_128_EXPORT40_WITH_MD5,
		CK_RC2_128_CBC_EXPORT40_WITH_MD5,
	}
}

func (cfg *Config) cipherSpecs() []CipherKind {
	if len(cfg.CipherSpecs) > 0 {
		return cfg.CipherSpecs
	}
	return DefaultServerCipherSpecs()
}

func (cfg *Config) newSessionID() ([]byte, error) {
	if cfg.SessionIDSource != nil {
		return cfg.SessionIDSource()
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (cfg *Config) newConnectionID() ([]byte, error) {
	if cfg.ConnectionIDSource != nil {
		return cfg.ConnectionIDSource()
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// negotiateServerCipher returns the server-preference-ordered cipher kind
// that also appears in the client's offered list and is supported here for
// bulk encryption.
func negotiateServerCipher(server, client []CipherKind) (CipherKind, error) {
	cset := make(map[CipherKind]bool, len(client))
	for _, k := range client {
		cset[k] = true
	}
	for _, k := range server {
		if cset[k] && k.IsSupportedForBulk() {
			return k, nil
		}
	}
	return 0, errors.New("ssl2: no mutually-supported cipher kind")
}

// ServerHandshakeResult captures what the server learned during the
// handshake.
type ServerHandshakeResult struct {
	ClientHello *ClientHello
	Cipher      CipherKind
}

// ServerHandshake drives the server side of an SSL 2.0 handshake on c using
// cfg. On success c is encrypted and ready for [Conn.Read] / [Conn.Write].
//
// The caller is responsible for setting any read deadline on the underlying
// net.Conn before calling.
func (c *Conn) ServerHandshake(cfg *Config) (*ServerHandshakeResult, error) {
	if cfg == nil {
		return nil, errors.New("ssl2: nil server Config")
	}
	if cfg.PrivateKey == nil {
		return nil, errors.New("ssl2: server Config.PrivateKey is nil")
	}
	if len(cfg.Certificate) == 0 {
		return nil, errors.New("ssl2: server Config.Certificate is empty")
	}

	ch, err := c.AcceptClientHello()
	if err != nil {
		return nil, fmt.Errorf("ssl2: reading CLIENT-HELLO: %w", err)
	}

	kind, err := negotiateServerCipher(cfg.cipherSpecs(), ch.CipherSpecs)
	if err != nil {
		// Inform the peer per spec, then surface the error.
		_ = c.SendError(ErrNoCipher)
		return nil, err
	}

	connID, err := cfg.newConnectionID()
	if err != nil {
		return nil, err
	}
	if len(connID) < 16 || len(connID) > 32 {
		return nil, fmt.Errorf("ssl2: ConnectionIDSource produced %d bytes (must be 16..32)", len(connID))
	}

	sh := &ServerHello{
		CertificateType: CertTypeX509,
		Version:         Version,
		Certificate:     cfg.Certificate,
		// Advertise the server's preference list intersected with the
		// client's offer. This matches what mainstream SSL 2.0 servers
		// (notably OpenSSL) historically did.
		CipherSpecs:  intersect(cfg.cipherSpecs(), ch.CipherSpecs),
		ConnectionID: connID,
	}
	if err := c.SendServerHello(sh); err != nil {
		return nil, fmt.Errorf("ssl2: writing SERVER-HELLO: %w", err)
	}

	cmkBytes, err := c.ReadRecord()
	if err != nil {
		return nil, fmt.Errorf("ssl2: reading CLIENT-MASTER-KEY: %w", err)
	}
	cmk, err := ParseClientMasterKey(cmkBytes)
	if err != nil {
		return nil, err
	}
	if cmk.CipherKind != kind {
		// The client picked a different cipher than we negotiated. SSL 2.0
		// allows the client free choice from the SERVER-HELLO list, so we
		// re-validate against the cipher actually selected.
		if !contains(sh.CipherSpecs, cmk.CipherKind) || !cmk.CipherKind.IsSupportedForBulk() {
			_ = c.SendError(ErrNoCipher)
			return nil, fmt.Errorf("ssl2: client selected cipher %s which we did not offer or do not support", cmk.CipherKind.Name())
		}
		kind = cmk.CipherKind
	}
	params, _ := kind.Params()

	if len(cmk.ClearKey) != params.ClearKeyBytes {
		return nil, fmt.Errorf("ssl2: CLEAR-KEY length %d, want %d for %s", len(cmk.ClearKey), params.ClearKeyBytes, kind.Name())
	}
	if params.IVBytes > 0 && len(cmk.KeyArg) != params.IVBytes {
		return nil, fmt.Errorf("ssl2: KEY-ARG length %d, want %d for %s", len(cmk.KeyArg), params.IVBytes, kind.Name())
	}

	secret, err := rsa.DecryptPKCS1v15(rand.Reader, cfg.PrivateKey, cmk.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("ssl2: decrypting SECRET-KEY: %w", err)
	}
	if len(secret) != params.SecretKeyBytes {
		return nil, fmt.Errorf("ssl2: SECRET-KEY length %d after RSA decrypt, want %d", len(secret), params.SecretKeyBytes)
	}

	master := append(append(make([]byte, 0, params.TotalKeyBytes()), cmk.ClearKey...), secret...)
	clientWriteKey, serverWriteKey, err := deriveKeyMaterial(master, ch.Challenge, connID, params.TotalKeyBytes())
	if err != nil {
		return nil, err
	}

	readCS, err := newCipherState(kind, clientWriteKey, cmk.KeyArg)
	if err != nil {
		return nil, err
	}
	writeCS, err := newCipherState(kind, serverWriteKey, cmk.KeyArg)
	if err != nil {
		return nil, err
	}
	// Per spec, sequence numbers count every record including the cleartext
	// handshake records. From the server's perspective:
	//   read_seq starts at 2 (CLIENT-HELLO=0, CLIENT-MASTER-KEY=1)
	//   write_seq starts at 1 (SERVER-HELLO=0)
	readCS.seq = 2
	writeCS.seq = 1

	c.mu.Lock()
	c.read = readCS
	c.write = writeCS
	c.mu.Unlock()

	// Encrypted SERVER-VERIFY: echo client's CHALLENGE.
	rec, err := writeCS.sealRecord((&ServerVerify{Challenge: ch.Challenge}).Marshal())
	if err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(rec); err != nil {
		return nil, fmt.Errorf("ssl2: writing SERVER-VERIFY: %w", err)
	}

	// Read encrypted CLIENT-FINISHED.
	hdr, body, err := readRecordRaw(c.conn)
	if err != nil {
		return nil, fmt.Errorf("ssl2: reading CLIENT-FINISHED: %w", err)
	}
	plain, err := readCS.openRecord(hdr, body)
	if err != nil {
		return nil, fmt.Errorf("ssl2: decrypting CLIENT-FINISHED: %w", err)
	}
	cf, err := ParseClientFinished(plain)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(cf.ConnectionID, connID) {
		return nil, errors.New("ssl2: CLIENT-FINISHED connection id mismatch")
	}

	// Encrypted SERVER-FINISHED with a fresh session id.
	sid, err := cfg.newSessionID()
	if err != nil {
		return nil, err
	}
	rec, err = writeCS.sealRecord((&ServerFinished{SessionID: sid}).Marshal())
	if err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(rec); err != nil {
		return nil, fmt.Errorf("ssl2: writing SERVER-FINISHED: %w", err)
	}

	c.mu.Lock()
	c.finished = true
	c.mu.Unlock()

	return &ServerHandshakeResult{ClientHello: ch, Cipher: kind}, nil
}

func intersect(a, b []CipherKind) []CipherKind {
	bset := make(map[CipherKind]bool, len(b))
	for _, k := range b {
		bset[k] = true
	}
	out := make([]CipherKind, 0, len(a))
	for _, k := range a {
		if bset[k] {
			out = append(out, k)
		}
	}
	return out
}

func contains(s []CipherKind, k CipherKind) bool {
	for _, x := range s {
		if x == k {
			return true
		}
	}
	return false
}

// Server is a minimal SSL 2.0 server that wraps a net.Listener and runs
// [Conn.ServerHandshake] on every accepted connection. It is intended for
// scanning honeypots, fuzz harnesses, and integration tests — NOT for
// production deployments (SSL 2.0 is broken; see [package ssl2] doc).
type Server struct {
	// Config is the server configuration. Required.
	Config *Config

	// Handler, if non-nil, is invoked for each connection after a
	// successful handshake. The Conn passed to Handler is encrypted; the
	// Handler is responsible for any application-level protocol and for
	// closing the Conn.
	//
	// If Handler is nil the server simply closes c after the handshake.
	Handler func(c *Conn, res *ServerHandshakeResult)

	// HandshakeTimeout, if non-zero, bounds the time allowed for each
	// incoming handshake.
	HandshakeTimeout time.Duration

	// ErrorLog, if non-nil, is called with non-fatal per-connection
	// errors. If nil, errors are silently dropped.
	ErrorLog func(remoteAddr net.Addr, err error)

	mu       sync.Mutex
	listener net.Listener
	closed   bool
}

// Serve accepts connections on l and handshakes each one. It returns when
// l.Accept returns a permanent error (e.g. after [Server.Close]).
func (s *Server) Serve(l net.Listener) error {
	if s.Config == nil {
		return errors.New("ssl2: Server.Config is nil")
	}
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()

	for {
		nc, err := l.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go s.serveOne(nc)
	}
}

func (s *Server) serveOne(nc net.Conn) {
	c := NewConn(nc)
	defer func() {
		if recover() != nil {
			_ = nc.Close()
		}
	}()
	if s.HandshakeTimeout > 0 {
		_ = nc.SetDeadline(time.Now().Add(s.HandshakeTimeout))
	}
	res, err := c.ServerHandshake(s.Config)
	if err != nil {
		if s.ErrorLog != nil {
			s.ErrorLog(nc.RemoteAddr(), err)
		}
		_ = nc.Close()
		return
	}
	if s.HandshakeTimeout > 0 {
		_ = nc.SetDeadline(time.Time{})
	}
	if s.Handler == nil {
		_ = c.Close()
		return
	}
	s.Handler(c, res)
}

// ListenAndServe binds a TCP listener at addr and calls [Server.Serve].
func (s *Server) ListenAndServe(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Close stops the server. Connections already in flight are not interrupted.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
