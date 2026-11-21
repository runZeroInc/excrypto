// Copyright (c) runZero, Inc.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
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
		p.EmptyALPN != PolicyDefault
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

	if p.MalformedServerName != PolicyDefault &&
		malformedServerName(hello.serverName, hello.serverNameTrailingDot) {
		if !c.refuse(p.MalformedServerName, alertUnrecognizedName) {
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
func (p *Personality) applyToServerHello(hello *serverHelloMsg, now time.Time) {
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
