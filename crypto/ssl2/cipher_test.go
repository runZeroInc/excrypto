// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2
// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import "testing"

func TestMessageTypeString(t *testing.T) {
	cases := map[MessageType]string{
		MsgError:              "ERROR",
		MsgClientHello:        "CLIENT-HELLO",
		MsgClientMasterKey:    "CLIENT-MASTER-KEY",
		MsgClientFinished:     "CLIENT-FINISHED",
		MsgServerHello:        "SERVER-HELLO",
		MsgServerVerify:       "SERVER-VERIFY",
		MsgServerFinished:     "SERVER-FINISHED",
		MsgRequestCertificate: "REQUEST-CERTIFICATE",
		MsgClientCertificate:  "CLIENT-CERTIFICATE",
		MessageType(99):       "UNKNOWN",
	}
	for m, want := range cases {
		if got := m.String(); got != want {
			t.Errorf("MessageType(%d).String() = %q, want %q", m, got, want)
		}
	}
}

func TestCipherKindNames(t *testing.T) {
	cases := []struct {
		kind   CipherKind
		name   string
		bits   int
		export bool
	}{
		{CK_RC4_128_WITH_MD5, "SSL_CK_RC4_128_WITH_MD5", 128, false},
		{CK_RC4_128_EXPORT40_WITH_MD5, "SSL_CK_RC4_128_EXPORT40_WITH_MD5", 128, true},
		{CK_RC2_128_CBC_WITH_MD5, "SSL_CK_RC2_128_CBC_WITH_MD5", 128, false},
		{CK_RC2_128_CBC_EXPORT40_WITH_MD5, "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5", 128, true},
		{CK_IDEA_128_CBC_WITH_MD5, "SSL_CK_IDEA_128_CBC_WITH_MD5", 128, false},
		{CK_DES_64_CBC_WITH_MD5, "SSL_CK_DES_64_CBC_WITH_MD5", 64, false},
		{CK_DES_192_EDE3_CBC_WITH_MD5, "SSL_CK_DES_192_EDE3_CBC_WITH_MD5", 192, false},
		{CipherKind(0xABCDEF), "SSL_CK_UNKNOWN", 0xCDEF, false},
	}
	for _, tc := range cases {
		if got := tc.kind.Name(); got != tc.name {
			t.Errorf("CipherKind(0x%06x).Name() = %q, want %q", uint32(tc.kind), got, tc.name)
		}
		if got := tc.kind.EffectiveKeyBits(); got != tc.bits {
			t.Errorf("CipherKind(0x%06x).EffectiveKeyBits() = %d, want %d", uint32(tc.kind), got, tc.bits)
		}
		if got := tc.kind.IsExport(); got != tc.export {
			t.Errorf("CipherKind(0x%06x).IsExport() = %v, want %v", uint32(tc.kind), got, tc.export)
		}
	}
}

func TestAllKnownCipherKinds(t *testing.T) {
	got := AllKnownCipherKinds()
	if len(got) != 7 {
		t.Fatalf("AllKnownCipherKinds() returned %d entries, want 7", len(got))
	}
	seen := make(map[CipherKind]bool, len(got))
	for _, k := range got {
		if seen[k] {
			t.Errorf("duplicate cipher kind %s", k.Name())
		}
		seen[k] = true
		if k.Name() == "SSL_CK_UNKNOWN" {
			t.Errorf("AllKnownCipherKinds returned unknown kind 0x%06x", uint32(k))
		}
	}
}

func TestErrorCodeString(t *testing.T) {
	cases := map[ErrorCode]string{
		ErrNoCipher:        "NO-CIPHER-ERROR",
		ErrNoCertificate:   "NO-CERTIFICATE-ERROR",
		ErrBadCertificate:  "BAD-CERTIFICATE-ERROR",
		ErrUnsupportedCert: "UNSUPPORTED-CERTIFICATE-TYPE-ERROR",
		ErrorCode(0xFFFF):  "UNKNOWN-ERROR(0xffff)",
	}
	for code, want := range cases {
		if got := code.String(); got != want {
			t.Errorf("ErrorCode(0x%04x).String() = %q, want %q", uint16(code), got, want)
		}
	}
	if got := ErrNoCipher.Error(); got != "ssl2: peer sent NO-CIPHER-ERROR" {
		t.Errorf("ErrNoCipher.Error() = %q", got)
	}
}
