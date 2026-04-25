// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"bytes"
	"strings"
	"testing"
)

// fixedClientHello is a real SSL 2.0 CLIENT-HELLO captured from openssl 0.9.8
// (s_client -ssl2). Bytes adapted to be self-describing here:
//
//	01                                  msg_type      = CLIENT-HELLO
//	00 02                               version       = 0x0002
//	00 15                               cs_len        = 21
//	00 00                               sid_len       = 0
//	00 10                               ch_len        = 16
//	01 00 80                            CK_RC4_128_WITH_MD5
//	02 00 80                            CK_RC4_128_EXPORT40
//	03 00 80                            CK_RC2_128_CBC
//	04 00 80                            CK_RC2_128_CBC_EXPORT40
//	05 00 80                            CK_IDEA_128_CBC
//	06 00 40                            CK_DES_64_CBC
//	07 00 c0                            CK_DES_192_EDE3_CBC
//	... 16 octets of challenge ...
var fixedClientHello = []byte{
	0x01, 0x00, 0x02, 0x00, 0x15, 0x00, 0x00, 0x00, 0x10,
	0x01, 0x00, 0x80, 0x02, 0x00, 0x80, 0x03, 0x00, 0x80,
	0x04, 0x00, 0x80, 0x05, 0x00, 0x80, 0x06, 0x00, 0x40,
	0x07, 0x00, 0xc0,
	0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
	0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
}

func TestParseFixedClientHello(t *testing.T) {
	c, err := ParseClientHello(fixedClientHello)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if c.Version != 0x0002 {
		t.Errorf("version = 0x%04x", c.Version)
	}
	if len(c.CipherSpecs) != 7 {
		t.Errorf("got %d cipher specs, want 7", len(c.CipherSpecs))
	}
	wantOrder := []CipherKind{
		CK_RC4_128_WITH_MD5,
		CK_RC4_128_EXPORT40_WITH_MD5,
		CK_RC2_128_CBC_WITH_MD5,
		CK_RC2_128_CBC_EXPORT40_WITH_MD5,
		CK_IDEA_128_CBC_WITH_MD5,
		CK_DES_64_CBC_WITH_MD5,
		CK_DES_192_EDE3_CBC_WITH_MD5,
	}
	for i, w := range wantOrder {
		if c.CipherSpecs[i] != w {
			t.Errorf("cipher[%d] = %s, want %s", i, c.CipherSpecs[i].Name(), w.Name())
		}
	}
	if len(c.SessionID) != 0 {
		t.Errorf("session id should be empty, got %x", c.SessionID)
	}
	if len(c.Challenge) != 16 {
		t.Errorf("challenge length = %d", len(c.Challenge))
	}
}

func TestClientHelloRoundTrip(t *testing.T) {
	in := &ClientHello{
		Version:     Version,
		CipherSpecs: AllKnownCipherKinds(),
		SessionID:   bytes.Repeat([]byte{0x33}, 16),
		Challenge:   bytes.Repeat([]byte{0x44}, 24),
	}
	wire, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out, err := ParseClientHello(wire)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if out.Version != in.Version {
		t.Errorf("version mismatch")
	}
	if !bytes.Equal(out.SessionID, in.SessionID) {
		t.Errorf("session_id mismatch")
	}
	if !bytes.Equal(out.Challenge, in.Challenge) {
		t.Errorf("challenge mismatch")
	}
	if len(out.CipherSpecs) != len(in.CipherSpecs) {
		t.Fatalf("cipher count: got %d want %d", len(out.CipherSpecs), len(in.CipherSpecs))
	}
	for i := range in.CipherSpecs {
		if in.CipherSpecs[i] != out.CipherSpecs[i] {
			t.Errorf("cipher[%d] mismatch", i)
		}
	}
}

func TestClientHelloMarshalErrors(t *testing.T) {
	cases := []struct {
		name string
		in   ClientHello
		want string
	}{
		{"short challenge", ClientHello{Version: Version, CipherSpecs: []CipherKind{CK_RC4_128_WITH_MD5}, Challenge: bytes.Repeat([]byte{1}, 8)}, "challenge length"},
		{"long challenge", ClientHello{Version: Version, CipherSpecs: []CipherKind{CK_RC4_128_WITH_MD5}, Challenge: bytes.Repeat([]byte{1}, 33)}, "challenge length"},
		{"no ciphers", ClientHello{Version: Version, Challenge: bytes.Repeat([]byte{1}, 16)}, "at least one cipher"},
		{"bad sid len", ClientHello{Version: Version, CipherSpecs: []CipherKind{CK_RC4_128_WITH_MD5}, SessionID: []byte{1, 2, 3}, Challenge: bytes.Repeat([]byte{1}, 16)}, "session_id length"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.in.Marshal()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestParseClientHelloErrors(t *testing.T) {
	// Wrong message type.
	if _, err := ParseClientHello([]byte{0x04, 0, 2, 0, 0, 0, 0, 0, 16}); err == nil {
		t.Error("expected error for wrong type")
	}
	// Truncated.
	if _, err := ParseClientHello([]byte{0x01, 0x00}); err == nil {
		t.Error("expected error for truncated hello")
	}
	// cipher_specs_length not multiple of 3.
	bad := []byte{0x01, 0, 2, 0, 4, 0, 0, 0, 16}
	bad = append(bad, make([]byte, 4+16)...)
	if _, err := ParseClientHello(bad); err == nil {
		t.Error("expected error for bad cs_len")
	}
	// Body shorter than declared.
	short := []byte{0x01, 0, 2, 0, 3, 0, 0, 0, 16, 0x01, 0x00, 0x80}
	if _, err := ParseClientHello(short); err == nil {
		t.Error("expected error for truncated body")
	}
}

func TestServerHelloRoundTrip(t *testing.T) {
	cert := bytes.Repeat([]byte{0xCA}, 512)
	in := &ServerHello{
		SessionIDHit:    false,
		CertificateType: CertTypeX509,
		Version:         Version,
		Certificate:     cert,
		CipherSpecs:     []CipherKind{CK_RC4_128_WITH_MD5, CK_DES_192_EDE3_CBC_WITH_MD5},
		ConnectionID:    bytes.Repeat([]byte{0x77}, 16),
	}
	wire, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out, err := ParseServerHello(wire)
	if err != nil {
		t.Fatalf("ParseServerHello: %v", err)
	}
	if out.CertificateType != CertTypeX509 || out.Version != Version {
		t.Errorf("header mismatch: %+v", out)
	}
	if !bytes.Equal(out.Certificate, cert) {
		t.Errorf("cert mismatch")
	}
	if !bytes.Equal(out.ConnectionID, in.ConnectionID) {
		t.Errorf("conn id mismatch")
	}
	if len(out.CipherSpecs) != 2 || out.CipherSpecs[0] != CK_RC4_128_WITH_MD5 {
		t.Errorf("ciphers mismatch: %v", out.CipherSpecs)
	}
}

func TestServerHelloMarshalErrors(t *testing.T) {
	in := &ServerHello{ConnectionID: []byte{1, 2, 3}}
	if _, err := in.Marshal(); err == nil {
		t.Error("expected connection_id length error")
	}
}

func TestParseServerHelloErrors(t *testing.T) {
	if _, err := ParseServerHello([]byte{0x01, 0, 1, 0, 2, 0, 0, 0, 0, 0, 16}); err == nil {
		t.Error("expected error for wrong msg type")
	}
	if _, err := ParseServerHello([]byte{0x04}); err == nil {
		t.Error("expected error for truncated")
	}
	// cs_len not multiple of 3.
	bad := []byte{0x04, 0, 1, 0, 2, 0, 0, 0, 4, 0, 16}
	bad = append(bad, make([]byte, 4+16)...)
	if _, err := ParseServerHello(bad); err == nil {
		t.Error("expected cs_len error")
	}
	// connection_id length out of range.
	short := []byte{0x04, 0, 1, 0, 2, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0}
	if _, err := ParseServerHello(short); err == nil {
		t.Error("expected conn_id length error")
	}
}

func TestClientMasterKeyRoundTrip(t *testing.T) {
	in := &ClientMasterKey{
		CipherKind:   CK_RC4_128_EXPORT40_WITH_MD5,
		ClearKey:     bytes.Repeat([]byte{0x11}, 11),
		EncryptedKey: bytes.Repeat([]byte{0x22}, 64),
		KeyArg:       nil,
	}
	wire, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out, err := ParseClientMasterKey(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if out.CipherKind != in.CipherKind {
		t.Errorf("cipher kind mismatch")
	}
	if !bytes.Equal(out.ClearKey, in.ClearKey) || !bytes.Equal(out.EncryptedKey, in.EncryptedKey) {
		t.Errorf("payload mismatch")
	}
}

func TestParseClientMasterKeyErrors(t *testing.T) {
	if _, err := ParseClientMasterKey([]byte{0x01}); err == nil {
		t.Error("expected wrong-type error")
	}
	if _, err := ParseClientMasterKey([]byte{0x02, 0, 0, 0}); err == nil {
		t.Error("expected truncated error")
	}
	short := []byte{0x02, 0x01, 0x00, 0x80, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00}
	if _, err := ParseClientMasterKey(short); err == nil {
		t.Error("expected body-shorter-than-declared error")
	}
}

func TestErrorMessageRoundTrip(t *testing.T) {
	for _, code := range []ErrorCode{ErrNoCipher, ErrNoCertificate, ErrBadCertificate, ErrUnsupportedCert} {
		wire := (&ServerError{Code: code}).Marshal()
		got, err := ParseError(wire)
		if err != nil {
			t.Fatalf("ParseError: %v", err)
		}
		if got.Code != code {
			t.Errorf("got %v, want %v", got.Code, code)
		}
	}
	if _, err := ParseError([]byte{0x00, 0x00}); err == nil {
		t.Error("expected truncated error")
	}
	if _, err := ParseError([]byte{0x01, 0x00, 0x01}); err == nil {
		t.Error("expected wrong-type error")
	}
}

func TestSimpleMessagesRoundTrip(t *testing.T) {
	cf := &ClientFinished{ConnectionID: bytes.Repeat([]byte{0x55}, 16)}
	if got, err := ParseClientFinished(cf.Marshal()); err != nil || !bytes.Equal(got.ConnectionID, cf.ConnectionID) {
		t.Errorf("CLIENT-FINISHED round-trip: %v / %x", err, got)
	}
	sv := &ServerVerify{Challenge: bytes.Repeat([]byte{0x66}, 16)}
	if got, err := ParseServerVerify(sv.Marshal()); err != nil || !bytes.Equal(got.Challenge, sv.Challenge) {
		t.Errorf("SERVER-VERIFY round-trip: %v / %x", err, got)
	}
	sf := &ServerFinished{SessionID: bytes.Repeat([]byte{0x77}, 16)}
	if got, err := ParseServerFinished(sf.Marshal()); err != nil || !bytes.Equal(got.SessionID, sf.SessionID) {
		t.Errorf("SERVER-FINISHED round-trip: %v / %x", err, got)
	}
	if _, err := ParseClientFinished([]byte{0x05}); err == nil {
		t.Error("expected wrong-type error from ParseClientFinished")
	}
	if _, err := ParseServerVerify([]byte{0x01}); err == nil {
		t.Error("expected wrong-type error from ParseServerVerify")
	}
	if _, err := ParseServerFinished([]byte{0x01}); err == nil {
		t.Error("expected wrong-type error from ParseServerFinished")
	}
}
