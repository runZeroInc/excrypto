// Copyright 2026 The excrypto Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Compatibility shims for downstream packages (e.g. crypto/ssl3/tls,
// ZGrab) that depend on excrypto-specific tls/ types removed during the
// go1.26.2 forward port.
//
// These types are intentionally minimal — wide handshake-log/JSON-tag
// reintroduction is tracked separately and lives outside this package.

package tls

import "github.com/runZeroInc/excrypto/crypto"

const (
	excryptoHashMD5    uint8 = 1
	excryptoHashSHA1   uint8 = 2
	excryptoHashSHA256 uint8 = 4
	excryptoHashSHA384 uint8 = 5
	excryptoHashSHA512 uint8 = 6

	excryptoSignatureRSA uint8 = 1
)

// SigAndHash mirrors the TLS 1.2 SignatureAndHashAlgorithm struct from
// RFC 5246 §A.4.1.
type SigAndHash struct {
	Signature, Hash uint8
}

// ClientCertificateRequest captures the contents of a TLS CertificateRequest
// message as observed by an excrypto-based client.
type ClientCertificateRequest struct {
	Raw                    []byte
	HasSignatureAndHash    bool
	CertificateTypes       []byte
	SignatureAndHashes     []SigAndHash
	CertificateAuthorities [][]byte
}

func (c *Conn) setClientCertificateRequest(certReq *certificateRequestMsg) {
	c.ClientCertificateRequested = true
	c.ClientCertificateRequest = &ClientCertificateRequest{
		Raw:                    slicesCloneBytes(certReq.marshalForRaw()),
		HasSignatureAndHash:    certReq.hasSignatureAlgorithm,
		CertificateTypes:       slicesCloneBytes(certReq.certificateTypes),
		SignatureAndHashes:     sigAndHashesFromSignatureSchemes(certReq.supportedSignatureAlgorithms),
		CertificateAuthorities: cloneCertificateAuthorities(certReq.certificateAuthorities),
	}
}

func (c *Conn) setClientCertificateRequestTLS13(certReq *certificateRequestMsgTLS13) {
	raw, _ := certReq.marshal()
	c.ClientCertificateRequested = true
	c.ClientCertificateRequest = &ClientCertificateRequest{
		Raw:                    slicesCloneBytes(raw),
		HasSignatureAndHash:    true,
		SignatureAndHashes:     sigAndHashesFromSignatureSchemes(certReq.supportedSignatureAlgorithms),
		CertificateAuthorities: cloneCertificateAuthorities(certReq.certificateAuthorities),
	}
}

func (m *certificateRequestMsg) marshalForRaw() []byte {
	raw, _ := m.marshal()
	return raw
}

func sigAndHashesFromSignatureSchemes(schemes []SignatureScheme) []SigAndHash {
	if len(schemes) == 0 {
		return nil
	}
	out := make([]SigAndHash, 0, len(schemes))
	for _, scheme := range schemes {
		sigType, hashFunc, err := typeAndHashFromSignatureScheme(scheme)
		if err != nil {
			continue
		}
		out = append(out, SigAndHash{Signature: sigTypeForClientCertificateRequest(sigType), Hash: hashForClientCertificateRequest(hashFunc)})
	}
	return out
}

func sigTypeForClientCertificateRequest(sigType uint8) uint8 {
	if sigType == signaturePKCS1v15 || sigType == signatureRSAPSS {
		return excryptoSignatureRSA
	}
	return sigType
}

func hashForClientCertificateRequest(hashFunc crypto.Hash) uint8 {
	switch hashFunc {
	case crypto.MD5:
		return excryptoHashMD5
	case crypto.SHA1:
		return excryptoHashSHA1
	case crypto.SHA256:
		return excryptoHashSHA256
	case crypto.SHA384:
		return excryptoHashSHA384
	case crypto.SHA512:
		return excryptoHashSHA512
	default:
		return 0
	}
}

func cloneCertificateAuthorities(in [][]byte) [][]byte {
	if len(in) == 0 {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = slicesCloneBytes(in[i])
	}
	return out
}

func slicesCloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
