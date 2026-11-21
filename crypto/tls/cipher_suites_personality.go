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
// They are deliberately not in [CipherSuites], [InsecureCipherSuites] or
// defaultCipherSuites, so no existing caller can reach them: a Config has to
// name one in Config.CipherSuites, which is what internal/tlsx does for the
// personality path and nothing else does. That keeps a default server's offer,
// and the bytes it puts on the wire, exactly as they were.

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

// personalityCipherSuites are appended to the package's suite table at init.
// Appending rather than editing the table in place keeps the diff against
// upstream to one line there.
var personalityCipherSuites = []*cipherSuite{
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheRSAKA,
		suiteECDHE | suiteTLS12 | suiteSHA384, cipherAES, macSHA384, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheECDSAKA,
		suiteECDHE | suiteECSign | suiteTLS12 | suiteSHA384, cipherAES, macSHA384, nil},
	{TLS_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, rsaKA,
		suiteTLS12, cipherAES, macSHA256, nil},
}

func init() {
	cipherSuites = append(cipherSuites, personalityCipherSuites...)
}
