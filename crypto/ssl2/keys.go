// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"crypto/md5"
	"errors"
	"fmt"
)

// CipherMode describes the bulk-cipher mode used by an SSL 2.0 cipher kind.
type CipherMode uint8

const (
	// ModeUnknown is returned for cipher kinds this package doesn't model.
	ModeUnknown CipherMode = iota
	// ModeStream covers the RC4 ciphers.
	ModeStream
	// ModeCBC covers the DES/3DES/RC2/IDEA ciphers.
	ModeCBC
)

// CipherParams describes the keying and bulk-cipher parameters of an SSL 2.0
// cipher kind. Reference: Hickman, "The SSL Protocol", §C.4.
type CipherParams struct {
	Mode CipherMode
	// ClearKeyBytes is the number of bytes of CLEAR-KEY-DATA sent in the
	// clear inside CLIENT-MASTER-KEY. This is non-zero for the export
	// (40-bit effective) ciphers.
	ClearKeyBytes int
	// SecretKeyBytes is the number of bytes of SECRET-KEY-DATA, which is
	// RSA-encrypted under the server's certificate public key.
	SecretKeyBytes int
	// BlockSize is the block size of the bulk cipher (0 for stream).
	BlockSize int
	// IVBytes is the size of KEY-ARG (the initial IV) sent inside
	// CLIENT-MASTER-KEY. Zero for stream ciphers.
	IVBytes int
}

// TotalKeyBytes is the master-key length: clear_key_data || secret_key_data.
func (p CipherParams) TotalKeyBytes() int { return p.ClearKeyBytes + p.SecretKeyBytes }

// Params returns the bulk-cipher parameters for c, or (zero, false) if the
// cipher kind is unknown to this package.
func (c CipherKind) Params() (CipherParams, bool) {
	switch c {
	case CK_RC4_128_WITH_MD5:
		return CipherParams{Mode: ModeStream, SecretKeyBytes: 16}, true
	case CK_RC4_128_EXPORT40_WITH_MD5:
		return CipherParams{Mode: ModeStream, ClearKeyBytes: 11, SecretKeyBytes: 5}, true
	case CK_RC2_128_CBC_WITH_MD5:
		return CipherParams{Mode: ModeCBC, SecretKeyBytes: 16, BlockSize: 8, IVBytes: 8}, true
	case CK_RC2_128_CBC_EXPORT40_WITH_MD5:
		return CipherParams{Mode: ModeCBC, ClearKeyBytes: 11, SecretKeyBytes: 5, BlockSize: 8, IVBytes: 8}, true
	case CK_DES_64_CBC_WITH_MD5:
		return CipherParams{Mode: ModeCBC, SecretKeyBytes: 8, BlockSize: 8, IVBytes: 8}, true
	case CK_DES_192_EDE3_CBC_WITH_MD5:
		return CipherParams{Mode: ModeCBC, SecretKeyBytes: 24, BlockSize: 8, IVBytes: 8}, true
	case CK_IDEA_128_CBC_WITH_MD5:
		// Recognized for parsing but no bulk-cipher implementation.
		return CipherParams{Mode: ModeCBC, SecretKeyBytes: 16, BlockSize: 8, IVBytes: 8}, true
	}
	return CipherParams{}, false
}

// IsSupportedForBulk reports whether this package can carry encrypted records
// using cipher kind c. (Currently all defined kinds except IDEA.)
func (c CipherKind) IsSupportedForBulk() bool {
	p, ok := c.Params()
	if !ok {
		return false
	}
	if c == CK_IDEA_128_CBC_WITH_MD5 {
		return false
	}
	return p.Mode == ModeStream || p.Mode == ModeCBC
}

// deriveKeyMaterial implements the SSL 2.0 key-derivation function, returning
// (clientWriteKey, serverWriteKey). It generates ceil(2*N/16) MD5 blocks of
// keying material (N = cipher.TotalKeyBytes()) and partitions them, matching
// OpenSSL's historical s2_enc.c behavior.
//
// KEY-MATERIAL-i = MD5( masterKey || ('0'+i) || challenge || connectionID )
//
// Per "The SSL Protocol" §1.2:
//
//	CLIENT-READ-KEY  = KEY-MATERIAL-0[0..N-1]   (= server-write)
//	CLIENT-WRITE-KEY = KEY-MATERIAL-1[0..N-1]
//
// i.e. the first N bytes of derived material form the server's write/client's
// read key, and the next N form the client's write/server's read key. (We
// only need 2*N bytes total; the iteration loop is structured so each MD5
// block contributes 16 bytes of output until the buffer is full.)
func deriveKeyMaterial(masterKey, challenge, connID []byte, n int) (clientWrite, serverWrite []byte, err error) {
	if n <= 0 {
		return nil, nil, errors.New("ssl2: zero-length key derivation")
	}
	total := 2 * n
	out := make([]byte, 0, ((total+15)/16)*16)
	for i := 0; len(out) < total; i++ {
		if i > 9 {
			return nil, nil, fmt.Errorf("ssl2: key material too long (%d bytes)", total)
		}
		h := md5.New()
		h.Write(masterKey)
		h.Write([]byte{byte('0' + i)})
		h.Write(challenge)
		h.Write(connID)
		out = h.Sum(out)
	}
	// First N bytes = server write / client read; next N = client write.
	return out[n : 2*n], out[:n], nil
}
