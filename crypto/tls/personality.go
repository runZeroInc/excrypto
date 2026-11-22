// Copyright (c) runZero, Inc.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"io"
	"slices"
	"time"
)

// A Personality describes the observable half of a TLS server handshake: the
// things a remote peer can see and measure without holding any key.
//
// Two servers that negotiate the same version with the same cipher suite still
// differ on the wire in ways an active fingerprinter reads off directly — which
// extensions the ServerHello carries and in what order, which suite is picked
// out of the same offer, whether the ServerHello random starts with a clock,
// and what the server does with parameters it does not like (alert, which
// alert, or a bare FIN). Those differences identify the stack. Go's own answers
// to all of them are fixed, so every Go server answers alike.
//
// A Personality is a description of another stack's answers, not an
// implementation of it: it changes what the server says, never how the
// handshake is secured. Every field is optional and the zero Personality
// changes nothing, so the zero value is also what a caller gets by leaving
// [Config.Personality] nil — the package then behaves exactly as it did before
// personalities existed.
//
// A Personality is read-only once it is set on a Config and may be shared by
// any number of connections.
type Personality struct {
	// Name labels the personality for the caller's own logging. It is never
	// sent and never inspected here.
	Name string

	// ServerHelloExtensionOrder lists ServerHello extension IDs in the order
	// this stack emits them. Extensions present in the handshake but missing
	// from the list keep their built-in order after the listed ones, so a
	// partial list is enough to pin the part that is observed. A nil list
	// leaves the built-in order alone.
	//
	// Ordering is applied to the bytes of the ServerHello only. It does not
	// change what was negotiated.
	ServerHelloExtensionOrder []uint16

	// OmitServerHelloExtensions lists ServerHello extension IDs this stack
	// does not emit. Where an extension carries a negotiated meaning the
	// omission is real rather than cosmetic: dropping
	// extensionExtendedMasterSecret (0x0017) turns extended master secret off
	// for the connection, dropping extensionSessionTicket (0x0023) turns
	// session tickets off, and dropping extensionALPN (0x0010) leaves the
	// connection with no negotiated protocol. The server never claims
	// something it is not doing.
	OmitServerHelloExtensions []uint16

	// ECPointFormats replaces the contents of the ec_point_formats extension
	// (0x000b). Go sends the single uncompressed format; OpenSSL-derived
	// stacks commonly send three. Nil keeps the built-in value. The
	// uncompressed format (0) is always used on the wire whatever is
	// advertised here, so this is an advertisement only.
	ECPointFormats []uint8

	// CipherSuitePreference is the server's own preference order for TLS 1.2
	// and below, strongest-first as this stack ranks them, applied strictly:
	// the first suite in this list the client also offered is selected. Suites
	// the package does not implement are skipped. Nil leaves Go's own
	// selection (which weighs the client's order and the hardware) alone.
	CipherSuitePreference []uint16

	// CipherSuitePreferenceTLS13 is the same for TLS 1.3, where Go otherwise
	// ignores Config.CipherSuites entirely.
	CipherSuitePreferenceTLS13 []uint16

	// CoalesceHandshakeFlight puts the whole plaintext server flight —
	// ServerHello, Certificate, any status or key exchange, the certificate
	// request and ServerHelloDone — into one handshake record, instead of
	// giving each message a record of its own.
	//
	// Windows does this and almost nothing else does: of the fingerprints in
	// one scan corpus, 108 of 121 Schannel services answered the TLS 1.2 probe
	// with a single record, against 2 of more than 7,000 OpenSSL, BoringSSL
	// and Go ones. A scanner that reads one record per message sees one reply
	// from Windows and two from everything else, so this is on its own a
	// Windows-or-not signal.
	//
	// It applies to TLS 1.2 and below, where that flight is in the clear.
	CoalesceHandshakeFlight bool

	// ServerHelloSessionID makes the server issue a 32-byte session ID in a
	// full TLS 1.2 handshake. Go issues one only when it is resuming, so its
	// ServerHello is 32 bytes shorter than almost every other stack's.
	//
	// It is worth more than its 32 bytes: runZero's fingerprint parser only
	// reports ServerHello extensions for a record over 85 bytes, so a
	// ServerHello without a session ID comes back with an empty extension
	// list whatever it carried — which is exactly how Go's extension order
	// has been hiding, and why matching a real device's recorded fingerprint
	// needs the ID as well as the order.
	//
	// The ID is not offered for resumption: this package resumes from tickets,
	// not from the session ID, so a client that offers one back gets a full
	// handshake, as it does from any server whose cache has dropped it.
	ServerHelloSessionID bool

	// ServerRandomTimestamp puts the current time, as a big-endian 32-bit Unix
	// timestamp, in the first four bytes of the ServerHello random — the
	// pre-TLS1.2 gmt_unix_time field, which some stacks still fill in and
	// which a fingerprinter reads back as a clock. It applies to TLS 1.2 and
	// below; TLS 1.3 reserves parts of the random for downgrade signalling and
	// is left alone.
	ServerRandomTimestamp bool

	// MaxFragmentLength says what the server does with a max_fragment_length
	// extension (RFC 6066) carrying a value outside the defined range 1..4.
	// Go ignores the extension entirely, which reads as PolicyAccept.
	// PolicyAlertIllegalParameter is what RFC 6066 requires and what
	// OpenSSL-derived stacks do.
	MaxFragmentLength RefusalPolicy

	// EmptyServerName says what the server does with a server_name extension
	// carrying an empty name list or an empty name. Go rejects the malformed
	// message with a decode_error alert, which is PolicyAlertDecodeError.
	EmptyServerName RefusalPolicy

	// MalformedServerName says what the server does with a server_name
	// extension carrying a name it cannot use: one with a NUL byte in it, one
	// longer than 255 bytes, or one with a trailing dot. Go rejects the
	// trailing dot with decode_error and takes the other two as ordinary
	// names. OpenSSL answers all three with unrecognized_name.
	//
	// This is about the shape of the name, not about whether the server has a
	// certificate for it: a server that serves one certificate to everyone
	// does not alert merely because the name is not its own, and neither does
	// this.
	MalformedServerName RefusalPolicy

	// LongServerName is MalformedServerName for the one shape several stacks
	// treat differently from the rest: a name longer than the 255 bytes a host
	// name can hold. An older JVM takes a name with a NUL in it as an ordinary
	// name and answers an over-long one with unexpected_message, where OpenSSL
	// answers both alike. Left at PolicyDefault it follows MalformedServerName.
	LongServerName RefusalPolicy

	// EmptyALPN says what the server does with an application_layer_protocol
	// _negotiation extension carrying an empty protocol list. Go rejects the
	// malformed message with decode_error.
	EmptyALPN RefusalPolicy

	// UnknownALPN says what the server does when the client offers only
	// protocols the server does not have. Go ignores ALPN when it has no
	// protocols configured, which is PolicyAccept; when it does have some, it
	// sends no_application_protocol.
	UnknownALPN RefusalPolicy

	// UnsupportedVersion says how the server refuses a client that offers no
	// version it will speak. Go sends protocol_version.
	UnsupportedVersion RefusalPolicy

	// UnsupportedVersionTooHigh is UnsupportedVersion for the other side of
	// the range: a client offering only versions above this server's ceiling,
	// where several stacks answer differently from how they answer one that is
	// too old. A TLS 1.2-only Siemens web server hangs up on a TLS 1.0-only
	// client and sends handshake_failure to a TLS 1.3-only one. Left at
	// PolicyDefault it follows UnsupportedVersion.
	UnsupportedVersionTooHigh RefusalPolicy

	// NoCommonCipherSuite says how the server refuses a client that offers no
	// suite it will use. Go sends handshake_failure.
	NoCommonCipherSuite RefusalPolicy

	// NoCommonKeyShareGroup says how the server refuses a TLS 1.3 client whose
	// supported_groups names no group this server will use — which in practice
	// means a client offering only a finite-field group. Go sends
	// handshake_failure, and so do OpenSSL 1.1 and BoringSSL; Schannel sends
	// nothing and closes.
	NoCommonKeyShareGroup RefusalPolicy

	// HalfCloseAlert says what the server sends when the client ends its half
	// of the stream in the middle of the handshake — a ClientHello followed by
	// a FIN, which is what a scanner does to see how the stack reacts to a
	// truncated handshake.
	//
	// Go sends nothing: the read fails and the connection is dropped. OpenSSL 3
	// answers decode_error, Java handshake_failure and GnuTLS
	// unexpected_message, and runZero's stack identification keys off exactly
	// that byte — a server that says nothing here cannot be identified as
	// OpenSSL 3 whatever else it does.
	//
	// The alert goes out after the server's own flight, so the peer sees the
	// flight and then the alert, as it does from the stacks being modelled.
	HalfCloseAlert RefusalPolicy

	// IgnoreSupportedVersions makes the server negotiate the version from the
	// ClientHello's legacy version field alone, as a stack that predates
	// RFC 8446 does — it has never heard of the supported_versions extension,
	// so an extension saying "TLS 1.2 only" does not stop it answering a
	// client whose legacy field says 0x0303 with a TLS 1.0 ServerHello.
	//
	// Windows Server 2008 R2 does exactly that: it answers the scanner's
	// TLS 1.2 probe at TLS 1.0, where this package refuses it, because the
	// probe's supported_versions names nothing the server will speak. A
	// personality with a pre-1.2 ceiling needs this or it hangs up on half the
	// probes the real machine answers.
	IgnoreSupportedVersions bool

	// FFDHE2048 makes the server complete a TLS 1.3 handshake over the RFC 7919
	// ffdhe2048 finite-field group when the client offers it.
	//
	// No Go TLS implements the finite-field groups, so a client offering only
	// ffdhe2048 is refused by every Go server — while essentially every real
	// OpenSSL 3 host answers it, which is one of the two things runZero's stack
	// identification uses to call a server OpenSSL 3 at all. The group is
	// offered only when a personality asks for it and only after every elliptic
	// curve the client and server share, so a client that offers a curve still
	// gets the curve.
	FFDHE2048 bool

	// CurvePreference is the server's own ECDHE group order at TLS 1.2 and
	// below, where this package otherwise takes the client's first supported
	// group. CurvePreferenceAES256 replaces it for suites with a 256-bit key:
	// Schannel answers an AES-256 suite over P-384 and an AES-128 suite over
	// X25519 from the same offer. Groups the client did not offer are skipped.
	CurvePreference       []CurveID
	CurvePreferenceAES256 []CurveID
}

// A RefusalPolicy is one answer to a parameter the server does not like: carry
// on, hang up, or send a particular alert.
//
// PolicyDefault, the zero value, means the package's own behaviour, so a
// Personality that says nothing about a case does not change it.
type RefusalPolicy uint8

// Refusal policies.
const (
	// PolicyDefault leaves the package's own behaviour in place.
	PolicyDefault RefusalPolicy = iota
	// PolicyAccept carries on with the handshake as though the parameter had
	// not been there. For a malformed parameter that means ignoring it.
	PolicyAccept
	// PolicyCloseNoAlert abandons the handshake without sending an alert, so
	// the peer sees the connection close. Several embedded stacks do this.
	PolicyCloseNoAlert
	// PolicyAlertDecodeError sends decode_error (50).
	PolicyAlertDecodeError
	// PolicyAlertIllegalParameter sends illegal_parameter (47).
	PolicyAlertIllegalParameter
	// PolicyAlertUnexpectedMessage sends unexpected_message (10).
	PolicyAlertUnexpectedMessage
	// PolicyAlertUnrecognizedName sends unrecognized_name (112).
	PolicyAlertUnrecognizedName
	// PolicyAlertHandshakeFailure sends handshake_failure (40).
	PolicyAlertHandshakeFailure
	// PolicyAlertProtocolVersion sends protocol_version (70).
	PolicyAlertProtocolVersion
	// PolicyAlertNoApplicationProtocol sends no_application_protocol (120).
	PolicyAlertNoApplicationProtocol
	// PolicyAlertInternalError sends internal_error (80).
	PolicyAlertInternalError
)

// alert returns the alert this policy sends, and whether it sends one at all.
func (p RefusalPolicy) alert() (alert, bool) {
	switch p {
	case PolicyAlertDecodeError:
		return alertDecodeError, true
	case PolicyAlertIllegalParameter:
		return alertIllegalParameter, true
	case PolicyAlertUnexpectedMessage:
		return alertUnexpectedMessage, true
	case PolicyAlertUnrecognizedName:
		return alertUnrecognizedName, true
	case PolicyAlertHandshakeFailure:
		return alertHandshakeFailure, true
	case PolicyAlertProtocolVersion:
		return alertProtocolVersion, true
	case PolicyAlertNoApplicationProtocol:
		return alertNoApplicationProtocol, true
	case PolicyAlertInternalError:
		return alertInternalError, true
	}
	return 0, false
}

// Clone returns a deep copy of p, or nil if p is nil.
func (p *Personality) Clone() *Personality {
	if p == nil {
		return nil
	}
	c := *p
	c.ServerHelloExtensionOrder = cloneSlice(p.ServerHelloExtensionOrder)
	c.OmitServerHelloExtensions = cloneSlice(p.OmitServerHelloExtensions)
	c.ECPointFormats = cloneSlice(p.ECPointFormats)
	c.CipherSuitePreference = cloneSlice(p.CipherSuitePreference)
	c.CipherSuitePreferenceTLS13 = cloneSlice(p.CipherSuitePreferenceTLS13)
	c.CurvePreference = cloneSlice(p.CurvePreference)
	c.CurvePreferenceAES256 = cloneSlice(p.CurvePreferenceAES256)
	return &c
}

func cloneSlice[T any](s []T) []T {
	if s == nil {
		return nil
	}
	return append([]T(nil), s...)
}

// omits reports whether this personality drops the given ServerHello
// extension. The nil personality drops nothing.
func (p *Personality) omits(ext uint16) bool {
	if p == nil {
		return false
	}
	for _, id := range p.OmitServerHelloExtensions {
		if id == ext {
			return true
		}
	}
	return false
}

// unsupportedVersion and noCommonCipherSuite read the two policies that are
// consulted on paths a nil Personality also reaches, so they are nil-safe.
func (p *Personality) unsupportedVersion() RefusalPolicy {
	if p == nil {
		return PolicyDefault
	}
	return p.UnsupportedVersion
}

func (p *Personality) noCommonCipherSuite() RefusalPolicy {
	if p == nil {
		return PolicyDefault
	}
	return p.NoCommonCipherSuite
}

// unsupportedVersionAbove is the policy for a client whose offer is entirely
// above this server's ceiling, falling back to the one for an offer that is
// too old when the personality does not distinguish them.
func (p *Personality) unsupportedVersionAbove() RefusalPolicy {
	if p == nil {
		return PolicyDefault
	}
	if p.UnsupportedVersionTooHigh != PolicyDefault {
		return p.UnsupportedVersionTooHigh
	}
	return p.UnsupportedVersion
}

// serverRandomTimestamp reports whether the ServerHello random should start
// with a clock.
func (p *Personality) serverRandomTimestamp() bool {
	return p != nil && p.ServerRandomTimestamp
}

// lenientClientHello reports whether the ClientHello parser should keep going
// past the malformed cases this personality has an opinion about, so that the
// opinion can be applied instead of the parser's blanket decode_error. Policies
// that happen to agree with the parser still take this path; the answer they
// produce is the same.
func (p *Personality) lenientClientHello() bool {
	if p == nil {
		return false
	}
	return p.EmptyServerName != PolicyDefault ||
		p.MalformedServerName != PolicyDefault ||
		p.LongServerName != PolicyDefault ||
		p.EmptyALPN != PolicyDefault
}

// serverNamePolicy returns the policy for a name this stack could not use,
// splitting out the over-long case for the stacks that answer it differently.
// It reports PolicyDefault for a name that is not malformed at all.
func (p *Personality) serverNamePolicy(name string, trailingDot bool) RefusalPolicy {
	if len(name) > 255 && p.LongServerName != PolicyDefault {
		return p.LongServerName
	}
	if !malformedServerName(name, trailingDot) {
		return PolicyDefault
	}
	return p.MalformedServerName
}

// malformedServerName reports whether name is one this stack could not use as
// a host name: it carries a NUL, runs past the 255 bytes a name list entry can
// hold in practice, or ends in a dot. The parser rejects the trailing dot on
// its own unless a personality asked it not to, so the flag it sets is passed
// in rather than re-derived.
func malformedServerName(name string, trailingDot bool) bool {
	if trailingDot || len(name) > 255 {
		return true
	}
	for i := 0; i < len(name); i++ {
		if name[i] == 0 {
			return true
		}
	}
	return false
}

// stamp writes a Unix timestamp over the first four bytes of random.
func stampServerRandom(random []byte, now time.Time) {
	if len(random) < 4 {
		return
	}
	t := uint32(now.Unix())
	random[0] = byte(t >> 24)
	random[1] = byte(t >> 16)
	random[2] = byte(t >> 8)
	random[3] = byte(t)
}

// orderServerHelloExtensions rewrites a marshalled ServerHello extension block
// into this personality's order, dropping any extension the personality omits.
//
// It parses the block it was just handed rather than threading an ordering
// through every builder in the ServerHello: the input is bytes this package
// produced a moment ago, so a parse failure means a bug here, and the block is
// returned untouched rather than mangled.
func (p *Personality) orderServerHelloExtensions(exts []byte) []byte {
	if p == nil || (len(p.ServerHelloExtensionOrder) == 0 && len(p.OmitServerHelloExtensions) == 0) {
		return exts
	}
	type ext struct {
		id   uint16
		body []byte // id and length included, ready to concatenate
	}
	var parsed []ext
	for rest := exts; len(rest) > 0; {
		if len(rest) < 4 {
			return exts // not something we wrote; leave it alone
		}
		id := uint16(rest[0])<<8 | uint16(rest[1])
		n := int(rest[2])<<8 | int(rest[3])
		if len(rest) < 4+n {
			return exts
		}
		parsed = append(parsed, ext{id: id, body: rest[:4+n]})
		rest = rest[4+n:]
	}

	out := make([]byte, 0, len(exts))
	used := make([]bool, len(parsed))
	for _, want := range p.ServerHelloExtensionOrder {
		for i := range parsed {
			if used[i] || parsed[i].id != want {
				continue
			}
			used[i] = true
			if !p.omits(parsed[i].id) {
				out = append(out, parsed[i].body...)
			}
		}
	}
	for i := range parsed {
		if used[i] || p.omits(parsed[i].id) {
			continue
		}
		out = append(out, parsed[i].body...)
	}
	return out
}

// personality returns the config's personality, or nil. It is nil-safe on the
// config so that callers need not care whether one was set.
func (c *Config) personality() *Personality {
	if c == nil {
		return nil
	}
	return c.Personality
}

// refuse applies a refusal policy at a point where the package would otherwise
// send fallback. It reports whether the caller should carry on (PolicyAccept),
// and otherwise has already sent whatever alert the policy calls for.
//
// PolicyAccept is not meaningful everywhere: where the handshake genuinely
// cannot continue — no mutual version, no mutual cipher suite — a caller that
// gets true still has to give up, and does so without an alert.
func (c *Conn) refuse(p RefusalPolicy, fallback alert) (carryOn bool) {
	switch p {
	case PolicyAccept:
		return true
	case PolicyCloseNoAlert:
		return false
	case PolicyDefault:
		c.sendAlert(fallback)
		return false
	}
	if a, ok := p.alert(); ok {
		c.sendAlert(a)
	}
	return false
}

// readAfterFlight reads the client's next handshake message once the server's
// own flight has gone out, answering a client that ends the stream there with
// whatever this personality's stack sends.
//
// A scanner's half-close probe is exactly this case: a ClientHello and then a
// FIN. Go reports the truncated read and sends nothing, which is what happens
// with no personality set or with one that has no opinion.
func (c *Conn) readAfterFlight(transcript transcriptHash) (any, error) {
	msg, err := c.readHandshake(transcript)
	if err == nil {
		return msg, nil
	}
	p := c.config.personality()
	if p == nil || p.HalfCloseAlert == PolicyDefault || !isEOFError(err) {
		return msg, err
	}
	if a, ok := p.HalfCloseAlert.alert(); ok {
		c.sendAlert(a)
	}
	return msg, err
}

// isEOFError reports whether err is the record layer running out of stream,
// which is what a peer's FIN looks like from inside a handshake.
func isEOFError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// ffdhe2048Group is the RFC 7919 2048-bit finite-field group, as a TLS
// supported_groups code point. It is the only finite-field group this package
// will serve, and only for a Personality that asks for it.
const ffdhe2048Group CurveID = 0x0100

// ffdhe2048 reports whether this personality serves the ffdhe2048 group.
func (p *Personality) ffdhe2048() bool { return p != nil && p.FFDHE2048 }

// ignoresSupportedVersions reports whether version negotiation should look
// only at the ClientHello's legacy version field.
func (p *Personality) ignoresSupportedVersions() bool {
	return p != nil && p.IgnoreSupportedVersions
}

// noCommonKeyShareGroup is the policy for a TLS 1.3 client that offers no group
// this server will use.
func (p *Personality) noCommonKeyShareGroup() RefusalPolicy {
	if p == nil {
		return PolicyDefault
	}
	return p.NoCommonKeyShareGroup
}

// errPersonalityRefused is the error behind a handshake a personality refused.
// The alert, if any, has already gone out by the time it is returned.
type personalityRefusal struct{ reason string }

func (e *personalityRefusal) Error() string {
	return "tls: personality refused the client hello: " + e.reason
}

// applyPersonalityToClientHello answers the ClientHello parameters this
// personality has an opinion about: the ones the parser was told to let
// through, and the max_fragment_length value the package otherwise ignores.
//
// It runs after version negotiation, so a client offering no version we speak
// is refused on the version before anything here is reached — which is the
// order the stacks being modelled use. With no personality set it does
// nothing, and with one set it only ever acts on a case the personality named.
func (c *Conn) applyPersonalityToClientHello(hello *clientHelloMsg) error {
	p := c.config.personality()
	if p == nil {
		return nil
	}

	// RFC 6066 defines max_fragment_length values 1..4 and requires anything
	// else to be refused with illegal_parameter. This package does not
	// implement the extension at all, so by default an out-of-range value goes
	// unremarked; a personality can say otherwise.
	if p.MaxFragmentLength != PolicyDefault && hello.hasMaxFragmentLength &&
		(hello.maxFragmentLength < 1 || hello.maxFragmentLength > 4) {
		if !c.refuse(p.MaxFragmentLength, alertIllegalParameter) {
			return &personalityRefusal{reason: "max_fragment_length out of range"}
		}
	}

	if hello.emptyServerName && p.EmptyServerName != PolicyDefault {
		if !c.refuse(p.EmptyServerName, alertDecodeError) {
			return &personalityRefusal{reason: "empty server_name"}
		}
	}

	if policy := p.serverNamePolicy(hello.serverName, hello.serverNameTrailingDot); policy != PolicyDefault {
		if !c.refuse(policy, alertUnrecognizedName) {
			return &personalityRefusal{reason: "malformed server_name"}
		}
		// Accepted: a name we cannot use is not a name. Dropping it here keeps
		// certificate selection and c.serverName from seeing it.
		hello.serverName = ""
	}

	if hello.emptyALPN && p.EmptyALPN != PolicyDefault {
		if !c.refuse(p.EmptyALPN, alertDecodeError) {
			return &personalityRefusal{reason: "empty ALPN protocol list"}
		}
	}

	if p.UnknownALPN != PolicyDefault && len(hello.alpnProtocols) > 0 {
		if proto, err := negotiateALPN(c.config.NextProtos, hello.alpnProtocols, false); err != nil || proto == "" {
			if !c.refuse(p.UnknownALPN, alertNoApplicationProtocol) {
				return &personalityRefusal{reason: "no ALPN protocol in common"}
			}
			// Accepted: this stack ignores an ALPN it cannot match. Dropping
			// the list here keeps the handshake's own negotiation, which would
			// send no_application_protocol when NextProtos is configured, from
			// overruling that.
			hello.alpnProtocols = nil
		}
	}

	return nil
}

// applyToServerHello stamps the personality's choices onto a ServerHello that
// has been filled in by the handshake: the extensions it drops, the ones whose
// contents it replaces, and the clock some stacks put in the random.
//
// Extensions that carry a negotiated meaning are dropped by clearing what was
// negotiated, not by hiding it, so the server never does something it did not
// say. Ordering is applied later, when the message is marshalled.
func (p *Personality) applyToServerHello(hello *serverHelloMsg, now time.Time, rand io.Reader) {
	if p == nil {
		return
	}
	hello.personality = p

	if p.omits(extensionExtendedMasterSecret) {
		hello.extendedMasterSecret = false
	}
	if p.omits(extensionRenegotiationInfo) {
		hello.secureRenegotiationSupported = false
		hello.secureRenegotiation = nil
	}
	if p.omits(extensionSessionTicket) {
		hello.ticketSupported = false
	}
	if p.omits(extensionALPN) {
		hello.alpnProtocol = ""
	}
	if p.omits(extensionServerName) {
		hello.serverNameAck = false
	}
	if p.omits(extensionStatusRequest) {
		hello.ocspStapling = false
	}
	if p.omits(extensionSupportedPoints) {
		hello.supportedPoints = nil
	} else if len(p.ECPointFormats) > 0 && len(hello.supportedPoints) > 0 {
		hello.supportedPoints = p.ECPointFormats
	}

	// A session ID in a full handshake. TLS 1.3 echoes the client's and is
	// left alone; so is a resumption, which has already set one.
	if p.ServerHelloSessionID && hello.supportedVersion == 0 && len(hello.sessionId) == 0 {
		id := make([]byte, 32)
		if _, err := io.ReadFull(rand, id); err == nil {
			hello.sessionId = id
		}
	}

	// gmt_unix_time. TLS 1.3 reserves the tail of the random for downgrade and
	// HelloRetryRequest signalling and treats the whole field as opaque, so
	// only the older negotiation gets a clock.
	if p.ServerRandomTimestamp && hello.supportedVersion == 0 {
		stampServerRandom(hello.random, now)
	}
}

// intersectSuites returns the suites in order that also appear in allowed,
// keeping order's order. A personality describes what a stack would choose; it
// does not widen what this Config permits, so a suite the Config rules out
// stays ruled out.
func intersectSuites(order, allowed []uint16) []uint16 {
	out := make([]uint16, 0, len(order))
	for _, id := range order {
		for _, a := range allowed {
			if id == a {
				out = append(out, id)
				break
			}
		}
	}
	return out
}

// aboveCeiling reports whether every version the client offered is newer than
// the newest this server speaks, as against a client that is simply too old.
func aboveCeiling(offered []uint16, max uint16) bool {
	if len(offered) == 0 || max == 0 {
		return false
	}
	for _, v := range offered {
		// GREASE values are not versions and are not evidence either way.
		if v&0x0f0f == 0x0a0a && v&0xff == v>>8 {
			continue
		}
		if v <= max {
			return false
		}
	}
	return true
}

// serverCurve returns the group this personality picks for suite out of the
// client's offer, or 0 to leave the choice to the client's order.
func (p *Personality) serverCurve(suite uint16, offered []CurveID, ok func(CurveID) bool) CurveID {
	if p == nil {
		return 0
	}
	pref := p.CurvePreference
	if cs := cipherSuiteByID(suite); cs != nil && cs.keyLen == 32 && len(p.CurvePreferenceAES256) > 0 {
		pref = p.CurvePreferenceAES256
	}
	for _, c := range pref {
		if slices.Contains(offered, c) && ok(c) {
			return c
		}
	}
	return 0
}
