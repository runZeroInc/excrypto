// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdh

import (
	"bytes"
	"errors"
	"sync"

	_ "github.com/runZeroInc/excrypto/crypto/internal/fips140/check"

	"github.com/runZeroInc/excrypto/crypto/internal/fips140"
)

var fipsSelfTest = sync.OnceFunc(func() {
	// Per IG D.F, Scenario 2, path (1).
	fips140.CAST("KAS-ECC-SSC P-256", func() error {
		privateKey := []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		}
		publicKey := []byte{
			0x04,
			0x51, 0x5c, 0x3d, 0x6e, 0xb9, 0xe3, 0x96, 0xb9,
			0x04, 0xd3, 0xfe, 0xca, 0x7f, 0x54, 0xfd, 0xcd,
			0x0c, 0xc1, 0xe9, 0x97, 0xbf, 0x37, 0x5d, 0xca,
			0x51, 0x5a, 0xd0, 0xa6, 0xc3, 0xb4, 0x03, 0x5f,
			0x45, 0x36, 0xbe, 0x3a, 0x50, 0xf3, 0x18, 0xfb,
			0xf9, 0xa5, 0x47, 0x59, 0x02, 0xa2, 0x21, 0x50,
			0x2b, 0xef, 0x0d, 0x57, 0xe0, 0x8c, 0x53, 0xb2,
			0xcc, 0x0a, 0x56, 0xf1, 0x7d, 0x9f, 0x93, 0x54,
		}
		want := []byte{
			0xb4, 0xf1, 0xfc, 0xce, 0x40, 0x73, 0x5f, 0x83,
			0x6a, 0xf8, 0xd6, 0x31, 0x2d, 0x24, 0x8d, 0x1a,
			0x83, 0x48, 0x40, 0x56, 0x69, 0xa1, 0x95, 0xfa,
			0xc5, 0x35, 0x04, 0x06, 0xba, 0x76, 0xbc, 0xce,
		}
		k := &PrivateKey{d: privateKey, pub: PublicKey{curve: p256}}
		peer := &PublicKey{curve: p256, q: publicKey}
		got, err := ecdh(P256(), k, peer)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			return errors.New("unexpected result")
		}
		return nil
	})
})
