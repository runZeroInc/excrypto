// Copyright 2026 The excrypto Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Handshake-log types and JSON wrappers, ported from
// github.com/runZeroInc/excrypto/crypto/ssl3/tls and adapted to the
// modern (Go 1.26) crypto/tls handshake-message field layout.
//
// All public log types in this file are prefixed with `Logged` or carry
// distinct names from the existing crypto/tls API (e.g. `LoggedCipherSuite`
// vs upstream's `CipherSuite` struct). The package-internal MakeLog
// methods are defined alongside the upstream message types in
// handshake_log_make.go.

package tls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	jsonKeys "github.com/runZeroInc/excrypto/crypto/json"
	"github.com/runZeroInc/excrypto/crypto/x509"
	"github.com/runZeroInc/excrypto/crypto/x509/ct"
)

// ErrUnimplementedCipher is reported when the handshake log is asked
// about a cipher suite that the local implementation does not carry.
var ErrUnimplementedCipher = errors.New("tls: unimplemented cipher suite")

// ErrNoMutualCipher is reported when no cipher suite is mutually
// acceptable to both peers.
var ErrNoMutualCipher = errors.New("tls: no mutual cipher suite")

// LoggedTLSVersion is the JSON-friendly wrapper for a TLS version
// (e.g. 0x0303 for TLS 1.2).
type LoggedTLSVersion uint16

// LoggedCipherSuite is the JSON-friendly wrapper for a TLS cipher
// suite codepoint.
type LoggedCipherSuite uint16

// LoggedCompressionMethod is the JSON-friendly wrapper for a TLS
// compression-method codepoint (RFC 3749 / RFC 5246 §6.2).
type LoggedCompressionMethod uint8

// LoggedPointFormat is the JSON-friendly wrapper for an EC point format
// (RFC 4492 §5.1.2).
type LoggedPointFormat uint8

// LoggedCurveID is the JSON-friendly wrapper for a TLS supported-group
// codepoint (RFC 4492 / RFC 7919 / RFC 8446).
type LoggedCurveID uint16

// SignatureAndHash is a JSON-marshaling wrapper for the legacy TLS 1.2
// SignatureAndHashAlgorithm (RFC 5246 §A.4.1) field pair.
type SignatureAndHash SigAndHash

// ClientHello is a JSON-marshalable summary of a TLS ClientHello message.
type ClientHello struct {
	Version              LoggedTLSVersion          `json:"version"`
	Random               []byte                    `json:"random"`
	SessionID            []byte                    `json:"session_id,omitempty"`
	CipherSuites         []LoggedCipherSuite       `json:"cipher_suites"`
	CompressionMethods   []LoggedCompressionMethod `json:"compression_methods"`
	OcspStapling         bool                      `json:"ocsp_stapling"`
	TicketSupported      bool                      `json:"ticket"`
	SecureRenegotiation  bool                      `json:"secure_renegotiation"`
	ExtendedMasterSecret bool                      `json:"extended_master_secret"`
	ServerName           string                    `json:"server_name,omitempty"`
	Scts                 bool                      `json:"scts"`
	SupportedCurves      []LoggedCurveID           `json:"supported_curves,omitempty"`
	SupportedPoints      []LoggedPointFormat       `json:"supported_point_formats,omitempty"`
	SessionTicket        *SessionTicket            `json:"session_ticket,omitempty"`
	SignatureAndHashes   []SignatureAndHash        `json:"signature_and_hashes,omitempty"`
	SignatureSchemes     []SignatureScheme         `json:"signature_schemes,omitempty"`
	SupportedVersions    []LoggedTLSVersion        `json:"supported_versions,omitempty"`
	AlpnProtocols        []string                  `json:"alpn_protocols,omitempty"`
	KeyShares            []LoggedKeyShare          `json:"key_shares,omitempty"`
}

// ServerHello is a JSON-marshalable summary of a TLS ServerHello.
type ServerHello struct {
	Version                     LoggedTLSVersion        `json:"version"`
	Random                      []byte                  `json:"random"`
	SessionID                   []byte                  `json:"session_id,omitempty"`
	CipherSuite                 LoggedCipherSuite       `json:"cipher_suite"`
	CompressionMethod           LoggedCompressionMethod `json:"compression_method"`
	OcspStapling                bool                    `json:"ocsp_stapling"`
	TicketSupported             bool                    `json:"ticket"`
	SecureRenegotiation         bool                    `json:"secure_renegotiation"`
	ExtendedMasterSecret        bool                    `json:"extended_master_secret"`
	SignedCertificateTimestamps []ParsedAndRawSCT       `json:"scts,omitempty"`
	AlpnProtocol                string                  `json:"alpn_protocol,omitempty"`
	SupportedVersion            LoggedTLSVersion        `json:"supported_version,omitempty"`
	ServerKeyShare              *LoggedKeyShare         `json:"server_key_share,omitempty"`
	SelectedIdentity            *uint16                 `json:"selected_psk_identity,omitempty"`
}

// LoggedKeyShare is a JSON-marshalable summary of a TLS 1.3 KeyShare entry.
type LoggedKeyShare struct {
	Group LoggedCurveID `json:"group"`
	Data  []byte        `json:"data,omitempty"`
}

// ParsedAndRawSCT pairs a raw SignedCertificateTimestamp blob with its
// parsed representation when available.
type ParsedAndRawSCT struct {
	Raw    []byte                         `json:"raw,omitempty"`
	Parsed *ct.SignedCertificateTimestamp `json:"parsed,omitempty"`
}

// SimpleCertificate carries both the raw DER and the parsed x509 form
// of a single certificate.
type SimpleCertificate struct {
	Raw    []byte            `json:"raw,omitempty"`
	Parsed *x509.Certificate `json:"parsed,omitempty"`
}

// Certificates represents a TLS Certificate message.
type Certificates struct {
	Certificate SimpleCertificate   `json:"certificate,omitempty"`
	Chain       []SimpleCertificate `json:"chain,omitempty"`
	Validation  *x509.Validation    `json:"validation,omitempty"`
}

// addParsed sets the parsed certificates and the validation. It assumes
// the chain slice has already been allocated (typically by certificateMsg.MakeLog).
func (c *Certificates) addParsed(certs []*x509.Certificate, validation *x509.Validation) {
	if len(certs) >= 1 {
		c.Certificate.Parsed = certs[0]
	}
	if len(certs) >= 2 {
		chain := certs[1:]
		for idx, cert := range chain {
			if idx < len(c.Chain) {
				c.Chain[idx].Parsed = cert
			}
		}
	}
	c.Validation = validation
}

// ServerKeyExchange captures a TLS 1.0–1.2 ServerKeyExchange message.
type ServerKeyExchange struct {
	Raw            []byte                 `json:"-"`
	RSAParams      *jsonKeys.RSAPublicKey `json:"rsa_params,omitempty"`
	DHParams       *jsonKeys.DHParams     `json:"dh_params,omitempty"`
	ECDHParams     *jsonKeys.ECDHParams   `json:"ecdh_params,omitempty"`
	Digest         []byte                 `json:"digest,omitempty"`
	Signature      *DigitalSignature      `json:"signature,omitempty"`
	SignatureError string                 `json:"signature_error,omitempty"`
}

// ClientKeyExchange captures a TLS 1.0–1.2 ClientKeyExchange message.
type ClientKeyExchange struct {
	Raw        []byte                    `json:"-"`
	RSAParams  *jsonKeys.RSAClientParams `json:"rsa_params,omitempty"`
	DHParams   *jsonKeys.DHParams        `json:"dh_params,omitempty"`
	ECDHParams *jsonKeys.ECDHParams      `json:"ecdh_params,omitempty"`
}

// Finished represents a TLS Finished message verify_data.
type Finished struct {
	VerifyData []byte `json:"verify_data"`
}

// SessionTicket represents the new session ticket sent by the server
// to the client, or the ticket the client included in its ClientHello.
type SessionTicket struct {
	Value        []uint8 `json:"value,omitempty"`
	Length       int     `json:"length,omitempty"`
	LifetimeHint uint32  `json:"lifetime_hint,omitempty"`
}

// MasterSecret is the master_secret derived during a TLS 1.0–1.2 handshake.
type MasterSecret struct {
	Value  []byte `json:"value,omitempty"`
	Length int    `json:"length,omitempty"`
}

// PreMasterSecret is the pre_master_secret used during a TLS 1.0–1.2
// handshake.
type PreMasterSecret struct {
	Value  []byte `json:"value,omitempty"`
	Length int    `json:"length,omitempty"`
}

// KeyMaterial captures the secrets negotiated during a TLS handshake.
type KeyMaterial struct {
	MasterSecret    *MasterSecret    `json:"master_secret,omitempty"`
	PreMasterSecret *PreMasterSecret `json:"pre_master_secret,omitempty"`
}

// EncryptedExtensions summarizes a TLS 1.3 EncryptedExtensions message.
type EncryptedExtensions struct {
	AlpnProtocol      string `json:"alpn_protocol,omitempty"`
	EarlyDataAccepted bool   `json:"early_data,omitempty"`
}

// CertificateRequest summarizes a TLS CertificateRequest message.
type CertificateRequest struct {
	CertificateTypes       []uint8            `json:"certificate_types,omitempty"`
	SignatureAndHashes     []SignatureAndHash `json:"signature_and_hashes,omitempty"`
	SignatureSchemes       []SignatureScheme  `json:"signature_schemes,omitempty"`
	CertificateAuthorities [][]byte           `json:"certificate_authorities,omitempty"`
}

// ServerHandshake stores all of the messages exchanged during a TLS
// handshake on a given [Conn]. It is populated by the handshake-driver
// code and exposed via [Conn.GetHandshakeLog].
//
// For TLS 1.0–1.2 every field that applies to the negotiated cipher
// suite is populated. For TLS 1.3 ServerKeyExchange/ClientKeyExchange
// are nil (TLS 1.3 has no equivalent on the wire); EncryptedExtensions,
// CertificateRequest and the server-side TLS 1.3 Certificates reach the
// log instead.
type ServerHandshake struct {
	ClientHello         *ClientHello         `json:"client_hello,omitempty"`
	ServerHello         *ServerHello         `json:"server_hello,omitempty"`
	EncryptedExtensions *EncryptedExtensions `json:"encrypted_extensions,omitempty"`
	ServerCertificates  *Certificates        `json:"server_certificates,omitempty"`
	ServerKeyExchange   *ServerKeyExchange   `json:"server_key_exchange,omitempty"`
	CertificateRequest  *CertificateRequest  `json:"certificate_request,omitempty"`
	ClientKeyExchange   *ClientKeyExchange   `json:"client_key_exchange,omitempty"`
	ClientCertificates  *Certificates        `json:"client_certificates,omitempty"`
	ClientFinished      *Finished            `json:"client_finished,omitempty"`
	SessionTicket       *SessionTicket       `json:"session_ticket,omitempty"`
	ServerFinished      *Finished            `json:"server_finished,omitempty"`
	KeyMaterial         *KeyMaterial         `json:"key_material,omitempty"`
}

// GetHandshakeLog returns the structured handshake transcript collected
// for this Conn (or nil if none has been recorded).
func (c *Conn) GetHandshakeLog() *ServerHandshake {
	return c.handshakeLog
}

// ensureHandshakeLog returns (and lazily initializes) c.handshakeLog.
func (c *Conn) ensureHandshakeLog() *ServerHandshake {
	if c.handshakeLog == nil {
		c.handshakeLog = &ServerHandshake{}
	}
	return c.handshakeLog
}

// MarshalJSON implements json.Marshaler for [LoggedTLSVersion].
func (v LoggedTLSVersion) MarshalJSON() ([]byte, error) {
	aux := struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}{
		Name:  loggedTLSVersionName(uint16(v)),
		Value: int(v),
	}
	return json.Marshal(&aux)
}

// UnmarshalJSON implements json.Unmarshaler for [LoggedTLSVersion].
func (v *LoggedTLSVersion) UnmarshalJSON(b []byte) error {
	aux := struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*v = LoggedTLSVersion(aux.Value)
	if expectedName := loggedTLSVersionName(uint16(*v)); expectedName != aux.Name {
		return fmt.Errorf("mismatched tls version and name: version: %d, name: %s, expected name: %s", aux.Value, aux.Name, expectedName)
	}
	return nil
}

func loggedTLSVersionName(v uint16) string {
	switch v {
	case VersionSSL30:
		return "SSLv3"
	case VersionTLS10:
		return "TLSv1.0"
	case VersionTLS11:
		return "TLSv1.1"
	case VersionTLS12:
		return "TLSv1.2"
	case VersionTLS13:
		return "TLSv1.3"
	}
	return fmt.Sprintf("unknown.0x%04X", v)
}

// MarshalJSON implements json.Marshaler for [LoggedCipherSuite].
func (cs LoggedCipherSuite) MarshalJSON() ([]byte, error) {
	buf := []byte{byte(cs >> 8), byte(cs)}
	enc := strings.ToUpper(hex.EncodeToString(buf))
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value int    `json:"value"`
	}{
		Hex:   "0x" + enc,
		Name:  nameForCipherSuite(uint16(cs)),
		Value: int(cs),
	}
	return json.Marshal(&aux)
}

// UnmarshalJSON implements json.Unmarshaler for [LoggedCipherSuite].
func (cs *LoggedCipherSuite) UnmarshalJSON(b []byte) error {
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint16 `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*cs = LoggedCipherSuite(aux.Value)
	return nil
}

// MarshalJSON implements json.Marshaler for [LoggedCompressionMethod].
func (cm LoggedCompressionMethod) MarshalJSON() ([]byte, error) {
	enc := strings.ToUpper(hex.EncodeToString([]byte{byte(cm)}))
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint8  `json:"value"`
	}{
		Hex:   "0x" + enc,
		Name:  nameForCompressionMethod(uint8(cm)),
		Value: uint8(cm),
	}
	return json.Marshal(aux)
}

// UnmarshalJSON implements json.Unmarshaler for [LoggedCompressionMethod].
func (cm *LoggedCompressionMethod) UnmarshalJSON(b []byte) error {
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint8  `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*cm = LoggedCompressionMethod(aux.Value)
	return nil
}

// MarshalJSON implements json.Marshaler for [LoggedPointFormat].
func (pf LoggedPointFormat) MarshalJSON() ([]byte, error) {
	aux := struct {
		Name  string `json:"name"`
		Value uint8  `json:"value"`
	}{
		Name:  nameForPointFormat(uint8(pf)),
		Value: uint8(pf),
	}
	return json.Marshal(aux)
}

// UnmarshalJSON implements json.Unmarshaler for [LoggedPointFormat].
func (pf *LoggedPointFormat) UnmarshalJSON(b []byte) error {
	aux := struct {
		Name  string `json:"name"`
		Value uint8  `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*pf = LoggedPointFormat(aux.Value)
	return nil
}

// MarshalJSON implements json.Marshaler for [LoggedCurveID].
func (id LoggedCurveID) MarshalJSON() ([]byte, error) {
	aux := struct {
		Name  string `json:"name"`
		Value uint16 `json:"value"`
	}{
		Name:  nameForCurve(uint16(id)),
		Value: uint16(id),
	}
	return json.Marshal(aux)
}

// UnmarshalJSON implements json.Unmarshaler for [LoggedCurveID].
func (id *LoggedCurveID) UnmarshalJSON(b []byte) error {
	aux := struct {
		Name  string `json:"name"`
		Value uint16 `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*id = LoggedCurveID(aux.Value)
	return nil
}

// MarshalJSON implements json.Marshaler for [SignatureAndHash].
func (sh SignatureAndHash) MarshalJSON() ([]byte, error) {
	aux := struct {
		SignatureAlgorithm string `json:"signature_algorithm"`
		HashAlgorithm      string `json:"hash_algorithm"`
	}{
		SignatureAlgorithm: nameForSignature(sh.Signature),
		HashAlgorithm:      nameForHash(sh.Hash),
	}
	return json.Marshal(&aux)
}

var unknownAlgorithmRegex = regexp.MustCompile(`unknown\.(\d+)`)

// UnmarshalJSON implements json.Unmarshaler for [SignatureAndHash].
func (sh *SignatureAndHash) UnmarshalJSON(b []byte) error {
	aux := struct {
		SignatureAlgorithm string `json:"signature_algorithm"`
		HashAlgorithm      string `json:"hash_algorithm"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	sh.Signature = signatureToName(aux.SignatureAlgorithm)
	sh.Hash = hashToName(aux.HashAlgorithm)
	return nil
}

// scts helper: deserialize raw bytes into a ParsedAndRawSCT slice.
func parsedAndRawSCTs(scts [][]byte) []ParsedAndRawSCT {
	if len(scts) == 0 {
		return nil
	}
	out := make([]ParsedAndRawSCT, 0, len(scts))
	for _, raw := range scts {
		entry := ParsedAndRawSCT{Raw: append([]byte(nil), raw...)}
		if parsed, err := ct.DeserializeSCT(bytes.NewReader(raw)); err == nil {
			entry.Parsed = parsed
		}
		out = append(out, entry)
	}
	return out
}
