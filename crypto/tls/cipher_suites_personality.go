// Copyright (c) runZero, Inc.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"hash"

	"github.com/runZeroInc/excrypto/crypto/hmac"
	"github.com/runZeroInc/excrypto/crypto/sha512"
)

// This file adds the three TLS 1.2 CBC suites this package has never
// implemented but that a [Personality] may need to select, because the stacks
// being modelled select them.
//
// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 is the sixth most common TLS 1.2 suite
// in the OT scan corpus — 3,003 of 113,150 services, ahead of
// ECDHE_ECDSA_AES_256_GCM — and it is what Windows Server 2012 R2 picks out of
// a standard offer. A server emulating that build and answering with
// ECDHE_RSA_AES_128_CBC_SHA256 instead is wrong in the one field a
// fingerprinter reads first.
//
// They are deliberately kept out of every list this package already has —
// cipherSuites, the two preference orders, [CipherSuites] and
// [InsecureCipherSuites] — and live in their own table instead. Two reasons:
//
// No existing caller can reach them. A Config has to name one in
// Config.CipherSuites, which internal/tlsx does for the personality path and
// nothing else does, so a default server's offer and the bytes it puts on the
// wire are exactly what they were.
//
// And the package's own tables say something these suites would contradict.
// TestCipherSuites requires the preference order to be totally ordered by the
// documented criteria, which have no term for the MAC's length: by those rules
// ECDHE_RSA_AES_256_CBC_SHA384 and ECDHE_RSA_AES_256_CBC_SHA are the same
// suite, and the test fails rather than choosing. That ranking is upstream's
// judgement about what a general-purpose stack should prefer, and it stays
// intact — these suites are not ranked, they are selected by name.

// Cipher suite IDs this package implements only for a Config that asks for
// them by name.
const (
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 uint16 = 0xc024
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   uint16 = 0xc028
	TLS_RSA_WITH_AES_256_CBC_SHA256         uint16 = 0x003d
)

// macSHA384 is the HMAC-SHA384 of a CBC suite's MAC-then-encrypt construction.
// The record layer is generic over the MAC's length, so nothing else changes.
func macSHA384(key []byte) hash.Hash {
	return hmac.New(sha512.New384, key)
}

// personalityCipherSuites is the table of suites this package implements but
// never offers of its own accord. cipherSuiteByID falls back to it, and
// Config.cipherSuites adds the ones a Config names.
var personalityCipherSuites = []*cipherSuite{
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheRSAKA,
		suiteECDHE | suiteTLS12 | suiteSHA384, cipherAES, macSHA384, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheECDSAKA,
		suiteECDHE | suiteECSign | suiteTLS12 | suiteSHA384, cipherAES, macSHA384, nil},
	{TLS_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, rsaKA,
		suiteTLS12, cipherAES, macSHA256, nil},
}

// personalityCipherSuiteByID returns one of these suites, or nil.
func personalityCipherSuiteByID(id uint16) *cipherSuite {
	for _, s := range personalityCipherSuites {
		if s.id == id {
			return s
		}
	}
	return nil
}

// namedPersonalityCipherSuites returns the IDs from this table that the given
// Config.CipherSuites names, in the table's order. A Config that names none —
// which is every caller that has not asked for one — gets nothing.
func namedPersonalityCipherSuites(configured []uint16) []uint16 {
	var out []uint16
	for _, s := range personalityCipherSuites {
		for _, id := range configured {
			if id == s.id {
				out = append(out, s.id)
				break
			}
		}
	}
	return out
}

// personalityCipherSuiteName is CipherSuiteName for these suites, which are in
// neither public list.
func personalityCipherSuiteName(id uint16) string {
	switch id {
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
	case TLS_RSA_WITH_AES_256_CBC_SHA256:
		return "TLS_RSA_WITH_AES_256_CBC_SHA256"
	}
	return ""
}
