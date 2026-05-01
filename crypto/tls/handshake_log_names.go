// Copyright 2026 The excrypto Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"strconv"
	"strings"
)

// Helper name tables used by the handshake-log JSON marshaling. Wire
// values follow the IANA registries (TLS 1.0–1.3); names match the
// IANA-canonical form where defined and otherwise the conventional
// Go/OpenSSL form.

// nameForCipherSuite returns the IANA name for a TLS cipher suite ID,
// or "unknown" when the ID is not recognized. The package also exposes
// [CipherSuiteName] (upstream) which returns "0x%04X" for unknown IDs;
// this helper preserves the ssl3-style "unknown" sentinel that the
// handshake-log JSON consumers expect.
func nameForCipherSuite(id uint16) string {
	if name := CipherSuiteName(id); !strings.HasPrefix(name, "0x") {
		return name
	}
	return "unknown"
}

// nameForCompressionMethod follows RFC 3749 / RFC 5246.
func nameForCompressionMethod(method uint8) string {
	switch method {
	case 0:
		return "NULL"
	case 1:
		return "DEFLATE"
	case 64:
		return "LZS"
	}
	return "unknown." + strconv.Itoa(int(method))
}

// nameForPointFormat follows RFC 4492 §5.1.2.
func nameForPointFormat(format uint8) string {
	switch format {
	case 0:
		return "uncompressed"
	case 1:
		return "ansiX962_compressed_prime"
	case 2:
		return "ansiX962_compressed_char2"
	}
	return "unknown." + strconv.Itoa(int(format))
}

// nameForCurve follows IANA "TLS Supported Groups" (RFC 4492 / RFC 7919 / RFC 8446).
func nameForCurve(id uint16) string {
	switch id {
	case 1:
		return "sect163k1"
	case 2:
		return "sect163r1"
	case 3:
		return "sect163r2"
	case 4:
		return "sect193r1"
	case 5:
		return "sect193r2"
	case 6:
		return "sect233k1"
	case 7:
		return "sect233r1"
	case 8:
		return "sect239k1"
	case 9:
		return "sect283k1"
	case 10:
		return "sect283r1"
	case 11:
		return "sect409k1"
	case 12:
		return "sect409r1"
	case 13:
		return "sect571k1"
	case 14:
		return "sect571r1"
	case 15:
		return "secp160k1"
	case 16:
		return "secp160r1"
	case 17:
		return "secp160r2"
	case 18:
		return "secp192k1"
	case 19:
		return "secp192r1"
	case 20:
		return "secp224k1"
	case 21:
		return "secp224r1"
	case 22:
		return "secp256k1"
	case 23:
		return "secp256r1"
	case 24:
		return "secp384r1"
	case 25:
		return "secp521r1"
	case 26:
		return "brainpoolP256r1"
	case 27:
		return "brainpoolP384r1"
	case 28:
		return "brainpoolP512r1"
	case 29:
		return "x25519"
	case 30:
		return "x448"
	case 256:
		return "ffdhe2048"
	case 257:
		return "ffdhe3072"
	case 258:
		return "ffdhe4096"
	case 259:
		return "ffdhe6144"
	case 260:
		return "ffdhe8192"
	case 0xFF01:
		return "arbitrary_explicit_prime_curves"
	case 0xFF02:
		return "arbitrary_explicit_char2_curves"
	}
	return "unknown." + strconv.Itoa(int(id))
}

// nameForSignature returns the human name for the legacy TLS 1.2
// SignatureAlgorithm wire codepoint (RFC 5246 §A.4.1).
func nameForSignature(sig uint8) string {
	switch sig {
	case 1:
		return "rsa"
	case 2:
		return "dsa"
	case 3:
		return "ecdsa"
	}
	return "unknown." + strconv.Itoa(int(sig))
}

// signatureToName is the inverse of [nameForSignature].
func signatureToName(name string) uint8 {
	switch name {
	case "rsa":
		return 1
	case "dsa":
		return 2
	case "ecdsa":
		return 3
	}
	if m := unknownAlgorithmRegex.FindStringSubmatch(name); len(m) == 2 {
		v, _ := strconv.Atoi(m[1])
		return uint8(v)
	}
	return 0
}

// nameForHash returns the human name for the legacy TLS 1.2 HashAlgorithm
// wire codepoint (RFC 5246 §A.4.1).
func nameForHash(h uint8) string {
	switch h {
	case 0:
		return "none"
	case 1:
		return "md5"
	case 2:
		return "sha1"
	case 3:
		return "sha224"
	case 4:
		return "sha256"
	case 5:
		return "sha384"
	case 6:
		return "sha512"
	}
	return "unknown." + strconv.Itoa(int(h))
}

// hashToName is the inverse of [nameForHash].
func hashToName(name string) uint8 {
	switch name {
	case "none":
		return 0
	case "md5":
		return 1
	case "sha1":
		return 2
	case "sha224":
		return 3
	case "sha256":
		return 4
	case "sha384":
		return 5
	case "sha512":
		return 6
	}
	if m := unknownAlgorithmRegex.FindStringSubmatch(name); len(m) == 2 {
		v, _ := strconv.Atoi(m[1])
		return uint8(v)
	}
	return 0
}

// nameForSignatureScheme returns the IANA name of a TLS 1.3
// SignatureScheme. For TLS 1.2-only mappings the legacy SigAndHash
// helpers are used instead.
func nameForSignatureScheme(scheme SignatureScheme) string {
	if s := scheme.String(); !strings.HasPrefix(s, "SignatureScheme(") {
		return s
	}
	return "unknown." + strconv.FormatUint(uint64(scheme), 10)
}
