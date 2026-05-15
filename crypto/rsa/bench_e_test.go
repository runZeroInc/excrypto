// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	. "github.com/runZeroInc/excrypto/crypto/rsa"
)

// BenchmarkVerifyByExponentBitLen measures the cost of a single PKCS#1 v1.5
// signature verification on a 2048-bit RSA modulus as E grows. The verifier
// performs m^e mod n; modular exponentiation is O(bitlen(e) · bitlen(n)²).
func BenchmarkVerifyByExponentBitLen(b *testing.B) {
	priv, err := GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	// Build a synthetic odd E of the requested bit length, coprime to phi(n)
	// is not required here: we measure CPU of the exponentiation itself, and
	// any odd E exercises the same code path.
	makeE := func(bits int) *big.Int {
		e := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		e.SetBit(e, 0, 1)
		return e
	}
	for _, bits := range []int{17, 64, 128, 256, 512, 1024, 2048} {
		b.Run("E="+itoa(bits)+"b", func(b *testing.B) {
			pub := &PublicKey{N: priv.N, E: makeE(bits)}
			msg := []byte("x")
			// Use Encrypt as a proxy for the public-key operation.
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = EncryptPKCS1v15(rand.Reader, pub, msg)
			}
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
