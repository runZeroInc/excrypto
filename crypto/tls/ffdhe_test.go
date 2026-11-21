// Copyright (c) runZero, Inc.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

// TestFFDHE2048Prime checks the group constant against the formula RFC 7919
// gives for it, rather than against another copy of the same hex: p = 2^2048 -
// 2^1984 + {[2^1918 * e] + 560316} * 2^64 - 1, where e is the base of the
// natural logarithm. A transcription error would survive a comparison with a
// transcription; it does not survive this.
func TestFFDHE2048Prime(t *testing.T) {
	if ffdhe2048P == nil {
		t.Fatal("the ffdhe2048 prime did not parse")
	}
	if ffdhe2048P.BitLen() != 2048 {
		t.Errorf("prime is %d bits, want 2048", ffdhe2048P.BitLen())
	}

	// [2^1918 * e], exactly. e = sum 1/k!, so N! * e is very nearly the integer
	// T(N) = sum_{k<=N} N!/k!, which satisfies T(N) = N*T(N-1) + 1. Taking the
	// quotient of 2^1918 * T(N) by N! in integer arithmetic gives the floor
	// with no accumulated rounding, as long as N is large enough that the tail
	// of the series cannot carry across an integer — 400 terms against a
	// 1918-bit scale is many times over.
	const n = 400
	tN, fact := big.NewInt(1), big.NewInt(1)
	for k := int64(1); k <= n; k++ {
		tN.Add(tN.Mul(tN, big.NewInt(k)), big.NewInt(1))
		fact.Mul(fact, big.NewInt(k))
	}
	floorE := new(big.Int).Div(new(big.Int).Lsh(tN, 1918), fact)
	want := new(big.Int).Lsh(big.NewInt(1), 2048)
	want.Sub(want, new(big.Int).Lsh(big.NewInt(1), 1984))
	want.Add(want, new(big.Int).Lsh(new(big.Int).Add(floorE, big.NewInt(560316)), 64))
	want.Sub(want, big.NewInt(1))
	if ffdhe2048P.Cmp(want) != 0 {
		t.Error("the ffdhe2048 prime is not the one RFC 7919 defines")
	}
	if !ffdhe2048P.ProbablyPrime(20) {
		t.Error("the ffdhe2048 prime is not prime")
	}
	// A safe prime: (p-1)/2 is prime too, which is what makes the only small
	// subgroup {1, p-1} and the range check sufficient.
	q := new(big.Int).Rsh(new(big.Int).Sub(ffdhe2048P, big.NewInt(1)), 1)
	if !q.ProbablyPrime(20) {
		t.Error("(p-1)/2 is not prime, so ffdhe2048 is not a safe-prime group")
	}
}

// TestFFDHE2048Agreement runs the client half by hand — this package does not
// implement one, since it never offers the group — and checks that both sides
// reach the same secret, that the shares are the fixed length RFC 8446 requires,
// and that a bad share is refused rather than used.
func TestFFDHE2048Agreement(t *testing.T) {
	ke := ffdheKeyExchange{}

	x, err := rand.Int(rand.Reader, new(big.Int).Sub(ffdhe2048P, big.NewInt(2)))
	if err != nil {
		t.Fatal(err)
	}
	x.Add(x, big.NewInt(1))
	clientShare := ffdhePad(new(big.Int).Exp(ffdhe2048G, x, ffdhe2048P))

	secret, serverShare, err := ke.serverSharedSecret(rand.Reader, clientShare)
	if err != nil {
		t.Fatal(err)
	}
	if serverShare.group != ffdhe2048Group {
		t.Errorf("server share group = %#04x, want %#04x", serverShare.group, ffdhe2048Group)
	}
	if len(serverShare.data) != ffdhe2048Size || len(secret) != ffdhe2048Size {
		t.Fatalf("share %d bytes and secret %d bytes, both have to be %d",
			len(serverShare.data), len(secret), ffdhe2048Size)
	}
	want := ffdhePad(new(big.Int).Exp(new(big.Int).SetBytes(serverShare.data), x, ffdhe2048P))
	if !bytes.Equal(secret, want) {
		t.Error("the two sides did not agree on the shared secret")
	}

	for _, bad := range []struct {
		name  string
		share []byte
	}{
		{"short", make([]byte, 128)},
		{"zero", make([]byte, ffdhe2048Size)},
		{"one", ffdhePad(big.NewInt(1))},
		{"p-1", ffdhePad(new(big.Int).Sub(ffdhe2048P, big.NewInt(1)))},
		{"p", ffdhePad(ffdhe2048P)},
	} {
		if _, _, err := ke.serverSharedSecret(rand.Reader, bad.share); err == nil {
			t.Errorf("a %s key share was accepted", bad.name)
		}
	}
}

// TestFFDHE2048IsNeverOfferedByDefault is the back-compatibility check for the
// group: it is in no preference order and no curve list, so a Config that has
// not asked for it cannot reach it, and keyShares refuses to produce one.
func TestFFDHE2048IsNeverOfferedByDefault(t *testing.T) {
	for _, id := range curvePreferenceOrder() {
		if id == ffdhe2048Group {
			t.Error("ffdhe2048 is in the default curve preference order")
		}
	}
	if (&Config{}).supportsCurve(VersionTLS13, ffdhe2048Group) {
		t.Error("a default Config says it supports ffdhe2048")
	}
	if _, _, err := (ffdheKeyExchange{}).keyShares(rand.Reader); err == nil {
		t.Error("the client half produced a key share for a group this package never offers")
	}
	if (&Personality{}).ffdhe2048() {
		t.Error("a personality with no opinion serves ffdhe2048")
	}
}

// TestPersonalityCipherSuitesAreOptIn checks the other half of the same
// promise: the CBC-SHA384 suites are reachable only by a Config that names
// them, and a Config that does not is offered exactly what it was before.
func TestPersonalityCipherSuitesAreOptIn(t *testing.T) {
	gated := []uint16{
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		TLS_RSA_WITH_AES_256_CBC_SHA256,
	}
	for _, id := range gated {
		if cipherSuiteByID(id) == nil {
			t.Errorf("%#04x: implemented but not resolvable", id)
		}
		if CipherSuiteName(id) == "" {
			t.Errorf("%#04x: no name", id)
		}
		for _, suites := range [][]uint16{
			(&Config{}).cipherSuites(true),
			(&Config{}).cipherSuites(false),
			(&Config{CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}}).cipherSuites(true),
		} {
			for _, got := range suites {
				if got == id {
					t.Errorf("%#04x: offered by a Config that did not name it", id)
				}
			}
		}
	}
	named := (&Config{CipherSuites: gated}).cipherSuites(true)
	for _, id := range gated {
		found := false
		for _, got := range named {
			found = found || got == id
		}
		if !found {
			t.Errorf("%#04x: not offered by a Config that named it", id)
		}
	}
}
