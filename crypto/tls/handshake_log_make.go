// Copyright 2026 The excrypto Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package-internal MakeLog methods that translate the handshake-message
// structs (handshake_messages.go) into JSON-marshalable log records
// (handshake_log.go).

package tls

import (
	"github.com/runZeroInc/excrypto/crypto/json"
)

// makeLog converts m into a [ClientHello] log entry.
func (m *clientHelloMsg) MakeLog() *ClientHello {
	if m == nil {
		return nil
	}
	ch := &ClientHello{
		Version:              LoggedTLSVersion(m.vers),
		Random:               append([]byte(nil), m.random...),
		SessionID:            append([]byte(nil), m.sessionId...),
		OcspStapling:         m.ocspStapling,
		TicketSupported:      m.ticketSupported,
		SecureRenegotiation:  m.secureRenegotiationSupported,
		ExtendedMasterSecret: m.extendedMasterSecret,
		ServerName:           m.serverName,
		Scts:                 m.scts,
	}
	ch.CipherSuites = make([]LoggedCipherSuite, len(m.cipherSuites))
	for i, c := range m.cipherSuites {
		ch.CipherSuites[i] = LoggedCipherSuite(c)
	}
	ch.CompressionMethods = make([]LoggedCompressionMethod, len(m.compressionMethods))
	for i, cm := range m.compressionMethods {
		ch.CompressionMethods[i] = LoggedCompressionMethod(cm)
	}
	ch.SupportedCurves = make([]LoggedCurveID, len(m.supportedCurves))
	for i, c := range m.supportedCurves {
		ch.SupportedCurves[i] = LoggedCurveID(c)
	}
	ch.SupportedPoints = make([]LoggedPointFormat, len(m.supportedPoints))
	for i, p := range m.supportedPoints {
		ch.SupportedPoints[i] = LoggedPointFormat(p)
	}
	if len(m.sessionTicket) > 0 {
		ch.SessionTicket = &SessionTicket{
			Value:  append([]byte(nil), m.sessionTicket...),
			Length: len(m.sessionTicket),
		}
	}
	if len(m.supportedSignatureAlgorithms) > 0 {
		ch.SignatureSchemes = append([]SignatureScheme(nil), m.supportedSignatureAlgorithms...)
		ch.SignatureAndHashes = sigAndHashesFromSchemes(m.supportedSignatureAlgorithms)
	}
	if len(m.supportedVersions) > 0 {
		ch.SupportedVersions = make([]LoggedTLSVersion, len(m.supportedVersions))
		for i, v := range m.supportedVersions {
			ch.SupportedVersions[i] = LoggedTLSVersion(v)
		}
	}
	if len(m.alpnProtocols) > 0 {
		ch.AlpnProtocols = append([]string(nil), m.alpnProtocols...)
	}
	if len(m.keyShares) > 0 {
		ch.KeyShares = make([]LoggedKeyShare, len(m.keyShares))
		for i, ks := range m.keyShares {
			ch.KeyShares[i] = LoggedKeyShare{
				Group: LoggedCurveID(ks.group),
				Data:  append([]byte(nil), ks.data...),
			}
		}
	}
	return ch
}

// MakeLog converts m into a [ServerHello] log entry.
func (m *serverHelloMsg) MakeLog() *ServerHello {
	if m == nil {
		return nil
	}
	sh := &ServerHello{
		Version:              LoggedTLSVersion(m.vers),
		Random:               append([]byte(nil), m.random...),
		SessionID:            append([]byte(nil), m.sessionId...),
		CipherSuite:          LoggedCipherSuite(m.cipherSuite),
		CompressionMethod:    LoggedCompressionMethod(m.compressionMethod),
		OcspStapling:         m.ocspStapling,
		TicketSupported:      m.ticketSupported,
		SecureRenegotiation:  m.secureRenegotiationSupported,
		ExtendedMasterSecret: m.extendedMasterSecret,
		AlpnProtocol:         m.alpnProtocol,
		SupportedVersion:     LoggedTLSVersion(m.supportedVersion),
	}
	if scts := parsedAndRawSCTs(m.scts); len(scts) > 0 {
		sh.SignedCertificateTimestamps = scts
	}
	if m.serverShare.group != 0 || len(m.serverShare.data) > 0 {
		sh.ServerKeyShare = &LoggedKeyShare{
			Group: LoggedCurveID(m.serverShare.group),
			Data:  append([]byte(nil), m.serverShare.data...),
		}
	}
	if m.selectedIdentityPresent {
		id := m.selectedIdentity
		sh.SelectedIdentity = &id
	}
	return sh
}

// MakeLog converts m into a [Certificates] log entry.
func (m *certificateMsg) MakeLog() *Certificates {
	c := &Certificates{}
	if len(m.certificates) >= 1 {
		c.Certificate.Raw = append([]byte(nil), m.certificates[0]...)
	}
	if len(m.certificates) >= 2 {
		chain := m.certificates[1:]
		c.Chain = make([]SimpleCertificate, len(chain))
		for i, raw := range chain {
			c.Chain[i].Raw = append([]byte(nil), raw...)
		}
	}
	return c
}

// makeLogTLS13 converts a TLS 1.3 certificate message into a [Certificates]
// log entry. The certificate field carries an already-parsed Certificate
// struct rather than a slice of DER blobs.
func (m *certificateMsgTLS13) MakeLog() *Certificates {
	c := &Certificates{}
	if len(m.certificate.Certificate) >= 1 {
		c.Certificate.Raw = append([]byte(nil), m.certificate.Certificate[0]...)
	}
	if len(m.certificate.Certificate) >= 2 {
		chain := m.certificate.Certificate[1:]
		c.Chain = make([]SimpleCertificate, len(chain))
		for i, raw := range chain {
			c.Chain[i].Raw = append([]byte(nil), raw...)
		}
	}
	return c
}

// MakeLog converts m into a [ServerKeyExchange] log entry.
func (m *serverKeyExchangeMsg) MakeLog(ka keyAgreement) *ServerKeyExchange {
	skx := &ServerKeyExchange{
		Raw: append([]byte(nil), m.key...),
	}
	switch ka := ka.(type) {
	case *rsaKeyAgreement:
		// RSA key transport has no SKX, but we surface the server's
		// long-term RSA pubkey for completeness.
		if ka.excryptoServerPub != nil {
			skx.RSAParams = &json.RSAPublicKey{PublicKey: ka.excryptoServerPub}
		}
	case *ecdheKeyAgreement:
		skx.ECDHParams = ecdheParamsFromKA(ka)
		if ka.excryptoSig != nil {
			skx.Signature = digitalSignatureFromKA(ka)
			if ka.excryptoSigError != nil {
				skx.SignatureError = ka.excryptoSigError.Error()
			}
		}
		skx.Digest = append([]byte(nil), ka.excryptoSignedData...)
	}
	return skx
}

// MakeLog converts m into a [ClientKeyExchange] log entry.
func (m *clientKeyExchangeMsg) MakeLog(ka keyAgreement) *ClientKeyExchange {
	ckx := &ClientKeyExchange{
		Raw: append([]byte(nil), m.ciphertext...),
	}
	switch ka := ka.(type) {
	case *rsaKeyAgreement:
		// CKX wire layout: 2-byte length || encrypted_pms.
		if len(m.ciphertext) >= 2 {
			ckx.RSAParams = &json.RSAClientParams{
				Length:       uint16(len(m.ciphertext) - 2),
				EncryptedPMS: append([]byte(nil), m.ciphertext[2:]...),
			}
		}
	case *ecdheKeyAgreement:
		ckx.ECDHParams = ecdheClientParamsFromKA(ka)
	}
	return ckx
}

// MakeLog converts m into a [Finished] log entry.
func (m *finishedMsg) MakeLog() *Finished {
	return &Finished{VerifyData: append([]byte(nil), m.verifyData...)}
}

// MakeLog converts m into a [SessionTicket] log entry.
func (m *newSessionTicketMsg) MakeLog() *SessionTicket {
	return &SessionTicket{
		Value:        append([]byte(nil), m.ticket...),
		Length:       len(m.ticket),
		LifetimeHint: 0, // newSessionTicketMsg uses lifetimeHint internally
	}
}

// MakeLog converts m into an [EncryptedExtensions] log entry.
func (m *encryptedExtensionsMsg) MakeLog() *EncryptedExtensions {
	return &EncryptedExtensions{
		AlpnProtocol:      m.alpnProtocol,
		EarlyDataAccepted: m.earlyData,
	}
}

// MakeLog converts m into a [CertificateRequest] log entry (TLS 1.0–1.2).
func (m *certificateRequestMsg) MakeLog() *CertificateRequest {
	cr := &CertificateRequest{
		CertificateTypes:       append([]uint8(nil), m.certificateTypes...),
		CertificateAuthorities: cloneByteSlices(m.certificateAuthorities),
	}
	if m.hasSignatureAlgorithm {
		cr.SignatureSchemes = append([]SignatureScheme(nil), m.supportedSignatureAlgorithms...)
		cr.SignatureAndHashes = sigAndHashesFromSchemes(m.supportedSignatureAlgorithms)
	}
	return cr
}

// MakeLog converts m into a [CertificateRequest] log entry (TLS 1.3).
func (m *certificateRequestMsgTLS13) MakeLog() *CertificateRequest {
	cr := &CertificateRequest{
		SignatureSchemes:       append([]SignatureScheme(nil), m.supportedSignatureAlgorithms...),
		SignatureAndHashes:     sigAndHashesFromSchemes(m.supportedSignatureAlgorithms),
		CertificateAuthorities: cloneByteSlices(m.certificateAuthorities),
	}
	return cr
}

// sigAndHashesFromSchemes converts a slice of TLS 1.3 SignatureSchemes
// into the legacy TLS 1.2 SignatureAndHashAlgorithm pairs that the
// handshake log surfaces.
func sigAndHashesFromSchemes(schemes []SignatureScheme) []SignatureAndHash {
	if len(schemes) == 0 {
		return nil
	}
	out := make([]SignatureAndHash, 0, len(schemes))
	for _, s := range schemes {
		sigType, hash, err := typeAndHashFromSignatureScheme(s)
		if err != nil {
			continue
		}
		pair := SignatureAndHash{
			Signature: sigTypeForClientCertificateRequest(sigType),
			Hash:      hashForClientCertificateRequest(hash),
		}
		out = append(out, pair)
	}
	return out
}

// cloneByteSlices makes a deep copy of a [][]byte.
func cloneByteSlices(in [][]byte) [][]byte {
	if len(in) == 0 {
		return nil
	}
	out := make([][]byte, len(in))
	for i, b := range in {
		out[i] = append([]byte(nil), b...)
	}
	return out
}
