// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRecordRoundTrip2ByteHeader(t *testing.T) {
	payloads := [][]byte{
		[]byte("a"),
		bytes.Repeat([]byte{0x42}, 127),
		bytes.Repeat([]byte{0x55}, 256),
		bytes.Repeat([]byte{0xAA}, 4096),
		bytes.Repeat([]byte{0xCC}, MaxRecordPayload),
	}
	for _, p := range payloads {
		var buf bytes.Buffer
		if err := writeRecord(&buf, p); err != nil {
			t.Fatalf("writeRecord(len=%d): %v", len(p), err)
		}
		// Top bit of first header byte must be set for 2-byte headers.
		if buf.Bytes()[0]&0x80 == 0 {
			t.Errorf("len=%d: header top bit not set", len(p))
		}
		hdr, got, err := readRecord(&buf)
		if err != nil {
			t.Fatalf("readRecord(len=%d): %v", len(p), err)
		}
		if hdr.hasPadding {
			t.Errorf("len=%d: round-trip should not introduce padding", len(p))
		}
		if hdr.length != len(p) {
			t.Errorf("len=%d: header length=%d", len(p), hdr.length)
		}
		if !bytes.Equal(got, p) {
			t.Errorf("len=%d: payload mismatch", len(p))
		}
	}
}

func TestRecordParse3ByteHeader(t *testing.T) {
	// Hand-craft a 3-byte-header record carrying 16 octets of payload, of
	// which 5 are padding. Length field encodes total payload+pad = 16.
	body := bytes.Repeat([]byte{0xEE}, 11)
	pad := bytes.Repeat([]byte{0x00}, 5)
	wire := append([]byte{0x00, 0x10, 0x05}, append(body, pad...)...)
	hdr, got, err := readRecord(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("readRecord: %v", err)
	}
	if !hdr.hasPadding || hdr.padLen != 5 || hdr.length != 16 {
		t.Errorf("hdr = %+v", hdr)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("payload = %x, want %x", got, body)
	}
}

func TestRecordParseEscapeBit(t *testing.T) {
	// 3-byte header with the security-escape bit set.
	wire := []byte{0x40, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04}
	hdr, got, err := readRecord(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("readRecord: %v", err)
	}
	if !hdr.isEscape {
		t.Errorf("expected escape bit set, got %+v", hdr)
	}
	if !bytes.Equal(got, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("payload mismatch")
	}
}

func TestRecordReadErrors(t *testing.T) {
	cases := []struct {
		name string
		wire []byte
		want string
	}{
		{"empty", []byte{}, ""},                    // io.EOF
		{"truncated 2-byte hdr", []byte{0x80}, ""}, // unexpected EOF
		{"zero length", []byte{0x80, 0x00}, "zero-length record"},
		{"truncated body", []byte{0x80, 0x05, 0x01, 0x02}, ""}, // unexpected EOF
		{"truncated 3-byte hdr", []byte{0x00, 0x05}, ""},       // unexpected EOF
		{"pad bigger than length", []byte{0x00, 0x02, 0x05, 0x01, 0x02}, "pad length 5 exceeds record length 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := readRecord(bytes.NewReader(tc.wire))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestRecordWriteErrors(t *testing.T) {
	if err := writeRecord(io.Discard, nil); err == nil {
		t.Error("writeRecord(empty) returned nil error")
	}
	too := bytes.Repeat([]byte{0}, MaxRecordPayload+1)
	if err := writeRecord(io.Discard, too); err == nil {
		t.Error("writeRecord(oversized) returned nil error")
	}
}

// errWriter rejects all writes — used to confirm we propagate I/O errors.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("io broken") }

func TestRecordWritePropagatesIOError(t *testing.T) {
	if err := writeRecord(errWriter{}, []byte{0x01}); err == nil {
		t.Error("expected I/O error to propagate")
	}
}
