// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"bytes"
	mrand "math/rand"
	"testing"

	rand "crypto/rand"
)

// Test cases are from RFC 4231, and match those present in the tests directory
// of the download here: https://nacl.cr.yp.to/install.html
var testCases = []struct {
	key [32]byte
	msg []byte
	out [32]byte
}{
	{
		key: [32]byte{
			0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			0x0b, 0x0b, 0x0b, 0x0b,
		},
		msg: []byte("Hi There"),
		out: [32]byte{
			0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d,
			0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0,
			0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78,
			0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde,
		},
	},
	{
		key: [32]byte{'J', 'e', 'f', 'e'},
		msg: []byte("what do ya want for nothing?"),
		out: [32]byte{
			0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2,
			0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56, 0xe0, 0xa3,
			0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6,
			0x10, 0x27, 0x0c, 0xd7, 0xea, 0x25, 0x05, 0x54,
		},
	},
	{
		key: [32]byte{
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa,
		},
		msg: []byte{ // 50 bytes of 0xdd
			0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
			0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
			0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
			0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
			0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
			0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
			0xdd, 0xdd,
		},
		out: [32]byte{
			0xfa, 0x73, 0xb0, 0x08, 0x9d, 0x56, 0xa2, 0x84,
			0xef, 0xb0, 0xf0, 0x75, 0x6c, 0x89, 0x0b, 0xe9,
			0xb1, 0xb5, 0xdb, 0xdd, 0x8e, 0xe8, 0x1a, 0x36,
			0x55, 0xf8, 0x3e, 0x33, 0xb2, 0x27, 0x9d, 0x39,
		},
	},
	{
		key: [32]byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19,
		},
		msg: []byte{
			0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
			0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
			0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
			0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
			0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
			0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
			0xcd, 0xcd,
		},
		out: [32]byte{
			0xb0, 0xba, 0x46, 0x56, 0x37, 0x45, 0x8c, 0x69,
			0x90, 0xe5, 0xa8, 0xc5, 0xf6, 0x1d, 0x4a, 0xf7,
			0xe5, 0x76, 0xd9, 0x7f, 0xf9, 0x4b, 0x87, 0x2d,
			0xe7, 0x6f, 0x80, 0x50, 0x36, 0x1e, 0xe3, 0xdb,
		},
	},
}

func TestSum(t *testing.T) {
	for i, test := range testCases {
		tag := Sum(test.msg, &test.key)
		if !bytes.Equal(tag[:], test.out[:]) {
			t.Errorf("#%d: Sum: got\n%x\nwant\n%x", i, tag, test.out)
		}
	}
}

func TestVerify(t *testing.T) {
	wrongMsg := []byte("unknown msg")

	for i, test := range testCases {
		if !Verify(test.out[:], test.msg, &test.key) {
			t.Errorf("#%d: Verify(%x, %q, %x) failed", i, test.out, test.msg, test.key)
		}
		if Verify(test.out[:], wrongMsg, &test.key) {
			t.Errorf("#%d: Verify(%x, %q, %x) unexpectedly passed", i, test.out, wrongMsg, test.key)
		}
	}
}

func TestStress(t *testing.T) {
	if testing.Short() {
		t.Skip("exhaustiveness test")
	}

	var key [32]byte
	msg := make([]byte, 10000)
	prng := mrand.New(mrand.NewSource(0))

	// copied from tests/auth5.c in nacl
	for i := 0; i < 10000; i++ {
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(msg[:i]); err != nil {
			t.Fatal(err)
		}
		tag := Sum(msg[:i], &key)
		if !Verify(tag[:], msg[:i], &key) {
			t.Errorf("#%d: unexpected failure from Verify", i)
		}
		if i > 0 {
			msgIndex := prng.Intn(i)
			oldMsgByte := msg[msgIndex]
			msg[msgIndex] += byte(1 + prng.Intn(255))
			if Verify(tag[:], msg[:i], &key) {
				t.Errorf("#%d: unexpected success from Verify after corrupting message", i)
			}
			msg[msgIndex] = oldMsgByte

			tag[prng.Intn(len(tag))] += byte(1 + prng.Intn(255))
			if Verify(tag[:], msg[:i], &key) {
				t.Errorf("#%d: unexpected success from Verify after corrupting authenticator", i)
			}
		}
	}
}

func BenchmarkAuth(b *testing.B) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 1024)
	if _, err := rand.Read(buf[:]); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tag := Sum(buf, &key)
		if Verify(tag[:], buf, &key) == false {
			b.Fatal("unexpected failure from Verify")
		}
	}
}
