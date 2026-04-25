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
