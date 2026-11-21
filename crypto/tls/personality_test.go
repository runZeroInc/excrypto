// Copyright (c) runZero, Inc.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// fullServerHello is a ServerHello carrying one of every extension this
// package emits for TLS 1.2, so that ordering and omission can be seen.
func fullServerHello() *serverHelloMsg {
	return &serverHelloMsg{
		vers:                         VersionTLS12,
		random:                       make([]byte, 32),
		sessionId:                    []byte{},
		cipherSuite:                  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		compressionMethod:            compressionNone,
		ocspStapling:                 true,
		ticketSupported:              true,
		secureRenegotiationSupported: true,
		extendedMasterSecret:         true,
		supportedPoints:              []uint8{pointFormatUncompressed},
		serverNameAck:                true,
	}
}

// helloExtensionIDs returns the extension IDs of a marshalled ServerHello, in
// the order they appear on the wire.
func helloExtensionIDs(t *testing.T, raw []byte) []uint16 {
	t.Helper()
	var m serverHelloMsg
	if !m.unmarshal(raw) {
		t.Fatalf("could not parse the ServerHello we just produced: %x", raw)
	}
	// unmarshal does not keep the order, so walk the bytes: handshake header
	// (4) + version (2) + random (32) + session ID + suite (2) + compression
	// (1) + extensions.
	b := raw[4+2+32:]
	if len(b) < 1 {
		t.Fatal("truncated ServerHello")
	}
	b = b[1+int(b[0]):]
	if len(b) < 3 {
		t.Fatal("truncated ServerHello")
	}
	b = b[3:]
	if len(b) == 0 {
		return nil // no extension block at all
	}
	if len(b) < 2 {
		t.Fatal("truncated ServerHello")
	}
	n := int(binary.BigEndian.Uint16(b))
	b = b[2 : 2+n]
	var ids []uint16
	for len(b) >= 4 {
		id := binary.BigEndian.Uint16(b)
		l := int(binary.BigEndian.Uint16(b[2:]))
		if len(b) < 4+l {
			t.Fatalf("truncated extension %#04x", id)
		}
		ids = append(ids, id)
		b = b[4+l:]
	}
	return ids
}

// TestPersonalityNilIsUnchanged is the back-compatibility check: a nil
// Personality, and an empty one, both have to leave the ServerHello exactly as
// this package has always produced it.
func TestPersonalityNilIsUnchanged(t *testing.T) {
	base := fullServerHello()
	want, err := base.marshal()
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range []*Personality{nil, {}, {Name: "no opinions"}} {
		m := fullServerHello()
		m.personality = p
		got, err := m.marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("personality %+v changed the ServerHello:\n got %x\nwant %x", p, got, want)
		}
	}
}

func TestPersonalityOrdersServerHelloExtensions(t *testing.T) {
	// What this package emits, which is the order under test.
	def := helloExtensionIDs(t, mustMarshal(t, fullServerHello()))
	if len(def) < 4 {
		t.Fatalf("expected several extensions by default, got %#04x", def)
	}

	// OpenSSL's order, as measured on devices in scan data:
	// renegotiation_info, server_name, ec_point_formats, extended_master_secret.
	m := fullServerHello()
	m.personality = &Personality{
		Name: "openssl-ish",
		ServerHelloExtensionOrder: []uint16{
			extensionRenegotiationInfo, extensionServerName,
			extensionSupportedPoints, extensionExtendedMasterSecret,
		},
	}
	got := helloExtensionIDs(t, mustMarshal(t, m))
	want := []uint16{
		extensionRenegotiationInfo, extensionServerName,
		extensionSupportedPoints, extensionExtendedMasterSecret,
	}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("extension order: got %#04x, want it to start %#04x", got, want)
		}
	}
	if len(got) != len(def) {
		t.Errorf("ordering dropped or added extensions: got %#04x, default %#04x", got, def)
	}
}

func TestPersonalityOmitsServerHelloExtensions(t *testing.T) {
	m := fullServerHello()
	m.personality = &Personality{
		Name: "no extensions at all",
		OmitServerHelloExtensions: []uint16{
			extensionRenegotiationInfo, extensionServerName,
			extensionSupportedPoints, extensionExtendedMasterSecret,
			extensionSessionTicket, extensionStatusRequest,
		},
	}
	// The omissions that carry a negotiated meaning are applied to the
	// message, not hidden at the last moment.
	m.personality.applyToServerHello(m, time.Now())
	if ids := helloExtensionIDs(t, mustMarshal(t, m)); len(ids) != 0 {
		t.Errorf("expected a ServerHello with no extensions, got %#04x", ids)
	}
	if m.extendedMasterSecret || m.ticketSupported || m.secureRenegotiationSupported {
		t.Error("an omitted extension must also be un-negotiated, not merely hidden")
	}
}

func TestPersonalityECPointFormats(t *testing.T) {
	m := fullServerHello()
	p := &Personality{ECPointFormats: []uint8{0, 1, 2}}
	p.applyToServerHello(m, time.Now())
	if len(m.supportedPoints) != 3 {
		t.Fatalf("ec_point_formats: got %v", m.supportedPoints)
	}
}

func TestPersonalityServerRandomTimestamp(t *testing.T) {
	now := time.Unix(1700000000, 0)

	m := fullServerHello()
	(&Personality{ServerRandomTimestamp: true}).applyToServerHello(m, now)
	if got := binary.BigEndian.Uint32(m.random[:4]); got != uint32(now.Unix()) {
		t.Errorf("gmt_unix_time: got %d, want %d", got, now.Unix())
	}

	// TLS 1.3 reserves parts of the random; it is left alone.
	m13 := fullServerHello()
	m13.supportedVersion = VersionTLS13
	(&Personality{ServerRandomTimestamp: true}).applyToServerHello(m13, now)
	if !bytes.Equal(m13.random[:4], []byte{0, 0, 0, 0}) {
		t.Errorf("TLS 1.3 random was stamped: %x", m13.random[:4])
	}
}

func TestIntersectSuites(t *testing.T) {
	got := intersectSuites([]uint16{3, 1, 9, 2}, []uint16{1, 2, 3})
	want := []uint16{3, 1, 2}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMalformedServerName(t *testing.T) {
	for _, tc := range []struct {
		name        string
		trailingDot bool
		want        bool
	}{
		{"example.com", false, false},
		{"example.com", true, true},
		{"example.com\x00", false, true},
		{string(make([]byte, 256)), false, true},
	} {
		if got := malformedServerName(tc.name, tc.trailingDot); got != tc.want {
			t.Errorf("malformedServerName(%q, %v) = %v", tc.name, tc.trailingDot, got)
		}
	}
}

// serverWriteRecorder copies everything the server writes, so a test can look
// at the ServerHello the peer actually saw.
type serverWriteRecorder struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *serverWriteRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.buf.Write(p)
	r.mu.Unlock()
	return r.Conn.Write(p)
}

func (r *serverWriteRecorder) written() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf.Bytes()...)
}

// serverHelloFromRecord pulls the ServerHello handshake message out of the
// first TLS record a server wrote.
func serverHelloFromRecord(t *testing.T, raw []byte) []byte {
	t.Helper()
	if len(raw) < 5 || recordType(raw[0]) != recordTypeHandshake {
		t.Fatalf("first record is not a handshake record: %x", raw[:min(len(raw), 16)])
	}
	n := int(binary.BigEndian.Uint16(raw[3:5]))
	if len(raw) < 5+n {
		t.Fatalf("short record")
	}
	body := raw[5 : 5+n]
	if len(body) < 4 || body[0] != typeServerHello {
		t.Fatalf("first handshake message is not a ServerHello: %x", body[:min(len(body), 16)])
	}
	l := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	return body[:4+l]
}

// TestPersonalityEndToEnd drives a real handshake and reads the extension
// order off the wire, which is what a fingerprinter sees.
func TestPersonalityEndToEnd(t *testing.T) {
	order := []uint16{extensionExtendedMasterSecret, extensionRenegotiationInfo}

	run := func(p *Personality) []uint16 {
		t.Helper()
		cli, srv := localPipe(t)
		rec := &serverWriteRecorder{Conn: srv}

		serverConfig := testConfigServer.Clone()
		serverConfig.MaxVersion = VersionTLS12
		serverConfig.Personality = p

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			server := Server(rec, serverConfig)
			_ = server.Handshake()
			server.Close()
		}()

		clientConfig := testConfigClient.Clone()
		clientConfig.MaxVersion = VersionTLS12
		clientConfig.ServerName = "test.golang.example"
		client := Client(cli, clientConfig)
		if err := client.Handshake(); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		state := client.ConnectionState()
		client.Close()
		wg.Wait()

		if p != nil && len(p.CipherSuitePreference) > 0 && state.CipherSuite != p.CipherSuitePreference[0] {
			t.Errorf("cipher: got %#04x, want %#04x", state.CipherSuite, p.CipherSuitePreference[0])
		}
		return helloExtensionIDs(t, serverHelloFromRecord(t, rec.written()))
	}

	def := run(nil)
	t.Logf("default ServerHello extensions: %#04x", def)

	got := run(&Personality{
		Name:                      "test",
		ServerHelloExtensionOrder: order,
		OmitServerHelloExtensions: []uint16{extensionServerName, extensionSessionTicket},
		CipherSuitePreference:     []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	})
	t.Logf("personality ServerHello extensions: %#04x", got)

	if fmt.Sprint(got) == fmt.Sprint(def) {
		t.Error("personality made no observable difference to the ServerHello")
	}
	for _, id := range got {
		if id == extensionServerName || id == extensionSessionTicket {
			t.Errorf("omitted extension %#04x was still sent", id)
		}
	}
	if len(got) >= 2 && (got[0] != order[0] || got[1] != order[1]) {
		t.Errorf("extension order: got %#04x, want it to start %#04x", got, order)
	}
}

// TestLenientClientHelloSurvivesUnmarshal guards the reset at the top of
// clientHelloMsg.unmarshal, which zeroes the message before parsing it: the
// leniency flag is set by the caller beforehand and has to survive that, or
// every policy about a malformed extension silently does nothing and the
// parser's own decode_error goes out instead.
func TestLenientClientHelloSurvivesUnmarshal(t *testing.T) {
	// A server_name extension holding one zero-length name.
	emptyName := []byte{0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00}
	// An ALPN extension holding an empty protocol list.
	emptyALPN := []byte{0x00, 0x10, 0x00, 0x02, 0x00, 0x00}

	build := func(ext []byte, lenient bool) *clientHelloMsg {
		m := &clientHelloMsg{lenient: lenient}
		var hello []byte
		hello = append(hello, 0x03, 0x03)
		hello = append(hello, make([]byte, 32)...)
		hello = append(hello, 0x00)                   // no session id
		hello = append(hello, 0x00, 0x02, 0x00, 0x2f) // one cipher suite
		hello = append(hello, 0x01, 0x00)             // null compression
		hello = append(hello, byte(len(ext)>>8), byte(len(ext)))
		hello = append(hello, ext...)
		msg := []byte{0x01, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}
		msg = append(msg, hello...)
		if !m.unmarshal(msg) {
			return nil
		}
		return m
	}

	for _, tc := range []struct {
		name  string
		ext   []byte
		check func(*clientHelloMsg) bool
	}{
		{"empty server_name", emptyName, func(m *clientHelloMsg) bool { return m.emptyServerName }},
		{"empty ALPN", emptyALPN, func(m *clientHelloMsg) bool { return m.emptyALPN }},
	} {
		if m := build(tc.ext, false); m != nil {
			t.Errorf("%s: the strict parser accepted it", tc.name)
		}
		m := build(tc.ext, true)
		if m == nil {
			t.Fatalf("%s: the lenient parser rejected it", tc.name)
		}
		if !tc.check(m) {
			t.Errorf("%s: the lenient parser did not record it", tc.name)
		}
	}
}

func TestAboveCeiling(t *testing.T) {
	for _, tc := range []struct {
		offered []uint16
		max     uint16
		want    bool
	}{
		{[]uint16{VersionTLS13}, VersionTLS12, true},
		{[]uint16{VersionTLS10}, VersionTLS12, false},
		{[]uint16{VersionTLS13, VersionTLS12}, VersionTLS12, false},
		{[]uint16{0x0a0a, VersionTLS13}, VersionTLS12, true},
		{nil, VersionTLS12, false},
	} {
		if got := aboveCeiling(tc.offered, tc.max); got != tc.want {
			t.Errorf("aboveCeiling(%#04x, %#04x) = %v, want %v", tc.offered, tc.max, got, tc.want)
		}
	}
}
