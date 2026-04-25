// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/runZeroInc/excrypto/crypto/des"
	"github.com/runZeroInc/excrypto/crypto/rc4"
	"github.com/runZeroInc/excrypto/crypto/ssl3/rc2"
)

// cipherState holds one half-duplex direction's bulk cipher + MAC secret +
// sequence number. It implements the on-the-wire encryption used after
// CLIENT-MASTER-KEY.
type cipherState struct {
	params CipherParams
	key    []byte // full master key for this direction (clear || secret)

	// Stream cipher state (one persistent RC4 instance per direction).
	stream *rc4.Cipher

	// Block cipher state.
	block cipher.Block
	iv    []byte // CBC residue (length = BlockSize)

	seq uint32
}

// newCipherState builds a per-direction state from the given key and the
// initial IV (KEY-ARG, sent in CLIENT-MASTER-KEY for block ciphers).
func newCipherState(kind CipherKind, key, iv []byte) (*cipherState, error) {
	p, ok := kind.Params()
	if !ok {
		return nil, fmt.Errorf("ssl2: unknown cipher kind 0x%06x", uint32(kind))
	}
	if len(key) != p.TotalKeyBytes() {
		return nil, fmt.Errorf("ssl2: cipher key length %d, want %d", len(key), p.TotalKeyBytes())
	}
	cs := &cipherState{params: p, key: append([]byte(nil), key...)}
	switch kind {
	case CK_RC4_128_WITH_MD5, CK_RC4_128_EXPORT40_WITH_MD5:
		c, err := rc4.NewCipher(key)
		if err != nil {
			return nil, err
		}
		cs.stream = c
	case CK_DES_64_CBC_WITH_MD5:
		b, err := des.NewCipher(key)
		if err != nil {
			return nil, err
		}
		cs.block = b
	case CK_DES_192_EDE3_CBC_WITH_MD5:
		b, err := des.NewTripleDESCipher(key)
		if err != nil {
			return nil, err
		}
		cs.block = b
	case CK_RC2_128_CBC_WITH_MD5:
		b, err := rc2.NewCipher(key)
		if err != nil {
			return nil, err
		}
		cs.block = b
	case CK_RC2_128_CBC_EXPORT40_WITH_MD5:
		b, err := rc2.NewCipherReducedStrength(key, 40)
		if err != nil {
			return nil, err
		}
		cs.block = b
	default:
		return nil, fmt.Errorf("ssl2: cipher kind %s not supported for bulk encryption", kind.Name())
	}
	if p.Mode == ModeCBC {
		if len(iv) != p.BlockSize {
			return nil, fmt.Errorf("ssl2: IV length %d, want block size %d", len(iv), p.BlockSize)
		}
		cs.iv = append([]byte(nil), iv...)
	}
	return cs, nil
}

// computeMAC returns MD5( key || data || padding || seq_be32 ).
// SSL 2.0 §1.4.2: MAC covers the clear payload + any padding + sequence #,
// using the full per-direction encryption key as the MAC secret.
func (cs *cipherState) computeMAC(data, padding []byte, seq uint32) []byte {
	h := md5.New()
	h.Write(cs.key)
	h.Write(data)
	h.Write(padding)
	var seqBE [4]byte
	binary.BigEndian.PutUint32(seqBE[:], seq)
	h.Write(seqBE[:])
	return h.Sum(nil)
}

// macSize is always 16 for the MD5 ciphers.
const macSize = md5.Size

// sealRecord encrypts data into a single SSL 2.0 record (header + ciphertext)
// using cs's parameters. It bumps cs.seq.
func (cs *cipherState) sealRecord(data []byte) ([]byte, error) {
	switch cs.params.Mode {
	case ModeStream:
		mac := cs.computeMAC(data, nil, cs.seq)
		cs.seq++
		body := make([]byte, len(mac)+len(data))
		copy(body, mac)
		copy(body[len(mac):], data)
		cs.stream.XORKeyStream(body, body)
		if len(body) > MaxRecordPayload {
			return nil, fmt.Errorf("ssl2: record body %d exceeds maximum", len(body))
		}
		out := make([]byte, 2+len(body))
		out[0] = 0x80 | byte(len(body)>>8)
		out[1] = byte(len(body))
		copy(out[2:], body)
		return out, nil
	case ModeCBC:
		bs := cs.params.BlockSize
		// Total = MAC || data || padding, multiple of BlockSize.
		preLen := macSize + len(data)
		padLen := bs - (preLen % bs)
		if padLen == bs {
			padLen = 0
		}
		padding := make([]byte, padLen)
		if padLen > 0 {
			if _, err := rand.Read(padding); err != nil {
				return nil, err
			}
		}
		mac := cs.computeMAC(data, padding, cs.seq)
		cs.seq++
		body := make([]byte, macSize+len(data)+padLen)
		copy(body, mac)
		copy(body[macSize:], data)
		copy(body[macSize+len(data):], padding)
		// CBC encrypt in place, chaining IV across records.
		enc := cipher.NewCBCEncrypter(cs.block, cs.iv)
		enc.CryptBlocks(body, body)
		// New IV = last ciphertext block.
		copy(cs.iv, body[len(body)-bs:])
		if len(body) > MaxRecordPayload {
			return nil, fmt.Errorf("ssl2: record body %d exceeds maximum", len(body))
		}
		// 3-byte header (escape bit clear, padding bit -> top 2 bits = 00).
		out := make([]byte, 3+len(body))
		out[0] = byte(len(body) >> 8) // top bit clear -> 3-byte header
		out[1] = byte(len(body))
		out[2] = byte(padLen)
		copy(out[3:], body)
		return out, nil
	}
	return nil, errors.New("ssl2: unknown cipher mode")
}

// openRecord decrypts a record body that was just read off the wire (after
// the header has been stripped). hdr describes the on-wire framing so we
// know whether padding was present. The returned slice is the cleartext
// payload (with MAC stripped and padding removed).
func (cs *cipherState) openRecord(hdr recordHeader, body []byte) ([]byte, error) {
	switch cs.params.Mode {
	case ModeStream:
		if len(body) < macSize {
			return nil, errors.New("ssl2: encrypted record shorter than MAC")
		}
		cs.stream.XORKeyStream(body, body)
		mac := body[:macSize]
		data := body[macSize:]
		want := cs.computeMAC(data, nil, cs.seq)
		cs.seq++
		if !constTimeEqual(mac, want) {
			return nil, errors.New("ssl2: bad record MAC")
		}
		return data, nil
	case ModeCBC:
		bs := cs.params.BlockSize
		if len(body)%bs != 0 || len(body) < macSize+bs {
			return nil, fmt.Errorf("ssl2: bad CBC body length %d", len(body))
		}
		// Save next IV (last ciphertext block) before in-place decrypt.
		nextIV := append([]byte(nil), body[len(body)-bs:]...)
		dec := cipher.NewCBCDecrypter(cs.block, cs.iv)
		dec.CryptBlocks(body, body)
		cs.iv = nextIV
		padLen := hdr.padLen
		if padLen > len(body)-macSize {
			return nil, errors.New("ssl2: pad length exceeds plaintext")
		}
		mac := body[:macSize]
		data := body[macSize : len(body)-padLen]
		padding := body[len(body)-padLen:]
		want := cs.computeMAC(data, padding, cs.seq)
		cs.seq++
		if !constTimeEqual(mac, want) {
			return nil, errors.New("ssl2: bad record MAC")
		}
		return data, nil
	}
	return nil, errors.New("ssl2: unknown cipher mode")
}

func constTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
