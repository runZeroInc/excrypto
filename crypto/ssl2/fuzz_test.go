// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"bytes"
	"testing"
)

// FuzzParseClientHello drives the CLIENT-HELLO parser with arbitrary inputs.
// We assert that it never panics and that any successful parse round-trips.
func FuzzParseClientHello(f *testing.F) {
	f.Add(fixedClientHello)
	f.Add([]byte{0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10})
	f.Fuzz(func(t *testing.T, data []byte) {
		ch, err := ParseClientHello(data)
		if err != nil {
			return
		}
		out, err := ch.Marshal()
		if err != nil {
			// Some valid-on-the-wire combinations (e.g. unusual session
			// id length) will be rejected by Marshal; that's intentional.
			return
		}
		// The re-parsed message must be identical.
		again, err := ParseClientHello(out)
		if err != nil {
			t.Fatalf("re-parse failed: %v", err)
		}
		if again.Version != ch.Version || !bytes.Equal(again.Challenge, ch.Challenge) {
			t.Fatalf("round-trip diverged")
		}
	})
}

func FuzzParseServerHello(f *testing.F) {
	good := (&ServerHello{
		CertificateType: CertTypeX509,
		Version:         Version,
		Certificate:     []byte{0x30, 0x03, 0x02, 0x01, 0x00},
		CipherSpecs:     []CipherKind{CK_RC4_128_WITH_MD5},
		ConnectionID:    bytes.Repeat([]byte{0x77}, 16),
	})
	wire, _ := good.Marshal()
	f.Add(wire)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseServerHello(data) // must not panic
	})
}

func FuzzParseClientMasterKey(f *testing.F) {
	good, _ := (&ClientMasterKey{
		CipherKind:   CK_RC4_128_WITH_MD5,
		ClearKey:     []byte{1, 2, 3},
		EncryptedKey: bytes.Repeat([]byte{4}, 64),
	}).Marshal()
	f.Add(good)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseClientMasterKey(data) // must not panic
	})
}

func FuzzReadRecord(f *testing.F) {
	f.Add([]byte{0x80, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05})
	f.Add([]byte{0x00, 0x05, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = readRecord(bytes.NewReader(data)) // must not panic
	})
}
