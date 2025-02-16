// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package drbg

import (
	"bytes"
	"errors"

	_ "github.com/runZeroInc/excrypto/crypto/internal/fips140/check"

	"github.com/runZeroInc/excrypto/crypto/internal/fips140"
)

func init() {
	// Per IG 10.3.A, Resolution 7: "A KAT of a DRBG may be performed by:
	// Instantiate with known data, Reseed with other known data, Generate and
	// then compare the result to a pre-computed value."
	fips140.CAST("CTR_DRBG", func() error {
		entropy := &[SeedSize]byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
			0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
		}
		reseedEntropy := &[SeedSize]byte{
			0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
			0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
			0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
			0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
			0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
		}
		additionalInput := &[SeedSize]byte{
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
			0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
			0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
			0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
			0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
			0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
		}
		want := []byte{
			0x6e, 0x6e, 0x47, 0x9d, 0x24, 0xf8, 0x6a, 0x3b,
			0x77, 0x87, 0xa8, 0xf8, 0x18, 0x6d, 0x98, 0x5a,
			0x53, 0xbe, 0xbe, 0xed, 0xde, 0xab, 0x92, 0x28,
			0xf0, 0xf4, 0xac, 0x6e, 0x10, 0xbf, 0x01, 0x93,
		}
		c := NewCounter(entropy)
		c.Reseed(reseedEntropy, additionalInput)
		got := make([]byte, len(want))
		c.Generate(got, additionalInput)
		if !bytes.Equal(got, want) {
			return errors.New("unexpected result")
		}
		return nil
	})
}
