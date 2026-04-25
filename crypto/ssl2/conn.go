// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/runZeroInc/excrypto/crypto/x509"
)

// Conn is a thin wrapper over a net.Conn that speaks SSL 2.0 records.
//
// It is intentionally simple: it provides synchronous read/write of single
// records, a high-level [Conn.Probe] that performs CLIENT-HELLO →
// SERVER-HELLO, and nothing else. It does NOT perform key exchange or
// bulk-data encryption.
type Conn struct {
	conn net.Conn
}

// NewConn wraps c in an SSL 2.0 [Conn]. The caller retains ownership of c
// and is responsible for closing it.
func NewConn(c net.Conn) *Conn {
	return &Conn{conn: c}
}

// NetConn returns the underlying net.Conn.
func (c *Conn) NetConn() net.Conn { return c.conn }

// SetDeadline is shorthand for c.NetConn().SetDeadline(t).
func (c *Conn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// WriteRecord writes payload as a single SSL 2.0 record.
func (c *Conn) WriteRecord(payload []byte) error {
	return writeRecord(c.conn, payload)
}

// ReadRecord reads a single SSL 2.0 record and returns its payload (with
// any padding stripped).
func (c *Conn) ReadRecord() ([]byte, error) {
	_, payload, err := readRecord(c.conn)
	return payload, err
}

// readRecordWithHeader is exposed for tests that want the parsed header.
func (c *Conn) readRecordWithHeader() (recordHeader, []byte, error) {
	return readRecord(c.conn)
}

// ProbeResult captures everything an SSL 2.0 probe can learn from a peer
// without completing key exchange.
type ProbeResult struct {
	// ServerHello is the parsed SERVER-HELLO returned by the peer (nil if
	// the peer responded with an ERROR or non-SSL2 traffic).
	ServerHello *ServerHello
	// Certificate is the parsed X.509 certificate from ServerHello, when
	// the certificate type is X.509 and parsing succeeds.
	Certificate *x509.Certificate
	// CertificateParseError is set if certificate-type was X.509 but the
	// DER could not be parsed by crypto/x509. The raw bytes are still
	// available in ServerHello.Certificate.
	CertificateParseError error
	// PeerError is populated if the peer responded with an SSL 2.0 ERROR
	// message instead of a SERVER-HELLO.
	PeerError *ServerError
}

// SupportsSSL2 reports whether the peer responded with a well-formed
// SERVER-HELLO (i.e. it speaks SSL 2.0).
func (r *ProbeResult) SupportsSSL2() bool {
	return r != nil && r.ServerHello != nil
}

// CipherKinds is a convenience accessor for the cipher kinds offered by
// the server. Returns nil if no SERVER-HELLO was received.
func (r *ProbeResult) CipherKinds() []CipherKind {
	if r == nil || r.ServerHello == nil {
		return nil
	}
	return r.ServerHello.CipherSpecs
}

// Probe sends a CLIENT-HELLO offering every well-known SSL 2.0 cipher and
// reads back the peer's SERVER-HELLO (or ERROR). The connection is left
// open so callers can inspect or close it as they see fit.
//
// challenge, if nil, is filled with 16 cryptographically-random bytes.
func (c *Conn) Probe(challenge []byte) (*ProbeResult, error) {
	if challenge == nil {
		challenge = make([]byte, 16)
		if _, err := rand.Read(challenge); err != nil {
			return nil, fmt.Errorf("ssl2: generating challenge: %w", err)
		}
	}
	hello := &ClientHello{
		Version:     Version,
		CipherSpecs: AllKnownCipherKinds(),
		Challenge:   challenge,
	}
	wire, err := hello.Marshal()
	if err != nil {
		return nil, err
	}
	if err := c.WriteRecord(wire); err != nil {
		return nil, fmt.Errorf("ssl2: writing CLIENT-HELLO: %w", err)
	}
	payload, err := c.ReadRecord()
	if err != nil {
		return nil, fmt.Errorf("ssl2: reading server response: %w", err)
	}
	if len(payload) == 0 {
		return nil, errors.New("ssl2: empty server response")
	}
	res := &ProbeResult{}
	switch MessageType(payload[0]) {
	case MsgServerHello:
		sh, err := ParseServerHello(payload)
		if err != nil {
			return nil, err
		}
		res.ServerHello = sh
		if sh.CertificateType == CertTypeX509 && len(sh.Certificate) > 0 {
			cert, perr := x509.ParseCertificate(sh.Certificate)
			if perr != nil {
				res.CertificateParseError = perr
			} else {
				res.Certificate = cert
			}
		}
	case MsgError:
		e, err := ParseError(payload)
		if err != nil {
			return nil, err
		}
		res.PeerError = e
	default:
		return nil, fmt.Errorf("ssl2: unexpected initial server message type %d", payload[0])
	}
	return res, nil
}

// Dial connects to addr (e.g. "example.com:443") via tcp and runs [Conn.Probe].
// The returned Conn is left open for further inspection; callers must close it.
//
// timeout, if non-zero, bounds the dial *and* the probe.
func Dial(addr string, timeout time.Duration) (*Conn, *ProbeResult, error) {
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
	if timeout > 0 {
		_ = c.SetDeadline(time.Time{})
	}
	return c, res, nil
}

// Close closes the underlying connection.
func (c *Conn) Close() error { return c.conn.Close() }

// Server-side helpers ────────────────────────────────────────────────────

// AcceptClientHello reads a single record from the peer and parses it as a
// CLIENT-HELLO. It is provided primarily for the in-process tests in this
// package and for fuzz/integration harnesses.
func (c *Conn) AcceptClientHello() (*ClientHello, error) {
	payload, err := c.ReadRecord()
	if err != nil {
		return nil, err
	}
	return ParseClientHello(payload)
}

// SendServerHello writes a SERVER-HELLO record to the peer.
func (c *Conn) SendServerHello(sh *ServerHello) error {
	wire, err := sh.Marshal()
	if err != nil {
		return err
	}
	return c.WriteRecord(wire)
}

// SendError writes an ERROR record to the peer.
func (c *Conn) SendError(code ErrorCode) error {
	return c.WriteRecord((&ServerError{Code: code}).Marshal())
}

// Compile-time check that *Conn does not accidentally implement io.ReadWriter
// (we deliberately do NOT expose Read/Write of plaintext, since SSL 2.0
// application data would be encrypted and we don't implement the cipher).
var _ = func() io.ReadWriter { return nil }
