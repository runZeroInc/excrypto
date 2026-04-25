// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

// Version is the on-the-wire SSL 2.0 protocol version.
//
// Some implementations (notably servers that "downgrade" to SSL 2.0 from a
// higher request) will echo back exactly the version offered. We accept any
// version whose major byte is 0x00 in [ParseServerHello]; callers that want
// to be strict can compare against [Version].
const Version uint16 = 0x0002

// MessageType identifies an SSL 2.0 handshake message.
//
// Reference: Hickman, "The SSL Protocol", §1.4 ("SSL Record Header Format")
// and §1.5 ("SSL Handshake Protocol").
type MessageType uint8

const (
	MsgError              MessageType = 0
	MsgClientHello        MessageType = 1
	MsgClientMasterKey    MessageType = 2
	MsgClientFinished     MessageType = 3
	MsgServerHello        MessageType = 4
	MsgServerVerify       MessageType = 5
	MsgServerFinished     MessageType = 6
	MsgRequestCertificate MessageType = 7
	MsgClientCertificate  MessageType = 8
)

// String returns the canonical SSL 2.0 message name.
func (m MessageType) String() string {
	switch m {
	case MsgError:
		return "ERROR"
	case MsgClientHello:
		return "CLIENT-HELLO"
	case MsgClientMasterKey:
		return "CLIENT-MASTER-KEY"
	case MsgClientFinished:
		return "CLIENT-FINISHED"
	case MsgServerHello:
		return "SERVER-HELLO"
	case MsgServerVerify:
		return "SERVER-VERIFY"
	case MsgServerFinished:
		return "SERVER-FINISHED"
	case MsgRequestCertificate:
		return "REQUEST-CERTIFICATE"
	case MsgClientCertificate:
		return "CLIENT-CERTIFICATE"
	default:
		return "UNKNOWN"
	}
}

// CertType identifies the certificate format carried in SERVER-HELLO and
// CLIENT-CERTIFICATE messages. SSL 2.0 only ever defined one value (X.509),
// but some implementations have been observed to send 0 when no certificate
// is available.
type CertType uint8

const (
	CertTypeNone CertType = 0
	CertTypeX509 CertType = 1
)

// CipherKind is a 3-octet SSL 2.0 cipher specification (often called a
// "CIPHER-KIND" in the Netscape draft). The high octet identifies the
// algorithm family; the low two octets carry the effective key size in bits
// encoded big-endian.
//
// Note that the SSL 3.0 / TLS 1.0+ cipher numbering is two octets and is
// disjoint from this 3-octet space. Do not confuse the two.
type CipherKind uint32

// The original Netscape draft defined seven cipher kinds. Values are taken
// from §C.4 of "The SSL Protocol".
const (
	CK_RC4_128_WITH_MD5              CipherKind = 0x010080
	CK_RC4_128_EXPORT40_WITH_MD5     CipherKind = 0x020080
	CK_RC2_128_CBC_WITH_MD5          CipherKind = 0x030080
	CK_RC2_128_CBC_EXPORT40_WITH_MD5 CipherKind = 0x040080
	CK_IDEA_128_CBC_WITH_MD5         CipherKind = 0x050080
	CK_DES_64_CBC_WITH_MD5           CipherKind = 0x060040
	CK_DES_192_EDE3_CBC_WITH_MD5     CipherKind = 0x0700C0
)

// AllKnownCipherKinds returns every CipherKind defined by the SSL 2.0 draft,
// in the canonical advertisement order used by historical clients (strongest
// first). Useful for [BuildClientHello] when probing.
func AllKnownCipherKinds() []CipherKind {
	return []CipherKind{
		CK_DES_192_EDE3_CBC_WITH_MD5,
		CK_RC4_128_WITH_MD5,
		CK_RC2_128_CBC_WITH_MD5,
		CK_IDEA_128_CBC_WITH_MD5,
		CK_DES_64_CBC_WITH_MD5,
		CK_RC4_128_EXPORT40_WITH_MD5,
		CK_RC2_128_CBC_EXPORT40_WITH_MD5,
	}
}

// Name returns the canonical SSL 2.0 cipher-spec name (e.g. "SSL_CK_RC4_128_WITH_MD5")
// or "SSL_CK_UNKNOWN(0xXXXXXX)" if the value is not one of the seven defined
// kinds.
func (c CipherKind) Name() string {
	switch c {
	case CK_RC4_128_WITH_MD5:
		return "SSL_CK_RC4_128_WITH_MD5"
	case CK_RC4_128_EXPORT40_WITH_MD5:
		return "SSL_CK_RC4_128_EXPORT40_WITH_MD5"
	case CK_RC2_128_CBC_WITH_MD5:
		return "SSL_CK_RC2_128_CBC_WITH_MD5"
	case CK_RC2_128_CBC_EXPORT40_WITH_MD5:
		return "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5"
	case CK_IDEA_128_CBC_WITH_MD5:
		return "SSL_CK_IDEA_128_CBC_WITH_MD5"
	case CK_DES_64_CBC_WITH_MD5:
		return "SSL_CK_DES_64_CBC_WITH_MD5"
	case CK_DES_192_EDE3_CBC_WITH_MD5:
		return "SSL_CK_DES_192_EDE3_CBC_WITH_MD5"
	}
	return "SSL_CK_UNKNOWN"
}

// EffectiveKeyBits returns the number of secret key bits used by this cipher
// (i.e. the bits the client must keep secret in CLIENT-MASTER-KEY). For
// "export" ciphers this is 40, even though the total key length is 128 bits.
func (c CipherKind) EffectiveKeyBits() int {
	return int(c & 0xFFFF)
}

// IsExport reports whether this cipher is a 40-bit US-export-grade cipher.
func (c CipherKind) IsExport() bool {
	switch c {
	case CK_RC4_128_EXPORT40_WITH_MD5, CK_RC2_128_CBC_EXPORT40_WITH_MD5:
		return true
	}
	return false
}
