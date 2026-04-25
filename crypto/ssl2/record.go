// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"errors"
	"fmt"
	"io"
)

// MaxRecordPayload is the largest plaintext payload that fits in a single
// SSL 2.0 record. Two-byte-header records can carry 2^15-1 octets, but
// most implementations cap the payload at 16 KiB. We accept up to the
// protocol maximum on read and emit a generous-but-bounded value on write.
const MaxRecordPayload = 32767

// recordHeader represents the 2- or 3-octet SSL 2.0 record-layer header.
//
//	2-byte header (no padding):
//	    byte 0:    1xxxxxxx     ─ top bit set; remainder = high 7 bits of length
//	    byte 1:    yyyyyyyy     ─ low 8 bits of length
//	3-byte header (block-cipher padded):
//	    byte 0:    01xxxxxx     ─ top bit clear, second bit signals "security
//	                              escape"; remainder = high 6 bits of length
//	    byte 1:    yyyyyyyy     ─ low 8 bits of length
//	    byte 2:    pppppppp     ─ pad-length octet
//
// The total record length is *length + padLen* octets of payload.
//
// Reference: "The SSL Protocol" §1.4.1.
type recordHeader struct {
	length     int
	padLen     int  // 0 for 2-byte headers
	hasPadding bool // false for 2-byte headers
	isEscape   bool // "security escape" bit (rarely used)
}

// readRecord reads a single SSL 2.0 record from r and returns the payload.
// The padding (if any) is stripped off and discarded.
//
// It returns the parsed header so callers can distinguish 2-byte and 3-byte
// records on the wire — useful for tests and forensics.
func readRecord(r io.Reader) (recordHeader, []byte, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:2]); err != nil {
		return recordHeader{}, nil, err
	}
	var h recordHeader
	if hdr[0]&0x80 != 0 {
		// 2-byte header.
		h.length = (int(hdr[0]&0x7f) << 8) | int(hdr[1])
	} else {
		// 3-byte header.
		h.hasPadding = true
		h.isEscape = hdr[0]&0x40 != 0
		h.length = (int(hdr[0]&0x3f) << 8) | int(hdr[1])
		if _, err := io.ReadFull(r, hdr[2:3]); err != nil {
			return recordHeader{}, nil, err
		}
		h.padLen = int(hdr[2])
	}
	if h.length == 0 {
		return h, nil, errors.New("ssl2: zero-length record")
	}
	if h.length > MaxRecordPayload {
		return h, nil, fmt.Errorf("ssl2: record length %d exceeds maximum %d", h.length, MaxRecordPayload)
	}
	if h.padLen > h.length {
		return h, nil, fmt.Errorf("ssl2: pad length %d exceeds record length %d", h.padLen, h.length)
	}
	buf := make([]byte, h.length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return h, nil, err
	}
	// In SSL 2.0 the *length* field counts ciphertext (data + padding);
	// for unencrypted handshake records padLen is always zero. We trim any
	// trailing pad in the unlikely event a server sent a padded clear-text
	// record.
	return h, buf[:len(buf)-h.padLen], nil
}

// writeRecord writes a single 2-byte-header SSL 2.0 record carrying payload.
// payload must be non-empty and at most MaxRecordPayload octets.
//
// We always emit 2-byte headers because every clear-text handshake message
// fits in this form and 3-byte headers are only meaningful once a block
// cipher has been negotiated (a state this package does not enter).
func writeRecord(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return errors.New("ssl2: refusing to write empty record")
	}
	if len(payload) > MaxRecordPayload {
		return fmt.Errorf("ssl2: payload length %d exceeds maximum %d", len(payload), MaxRecordPayload)
	}
	hdr := []byte{
		0x80 | byte(len(payload)>>8),
		byte(len(payload)),
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
