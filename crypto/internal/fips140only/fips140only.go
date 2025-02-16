// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fips140only

import (
	"hash"
	"internal/godebug"
	"io"

	"github.com/runZeroInc/excrypto/crypto/internal/fips140/drbg"
	"github.com/runZeroInc/excrypto/crypto/internal/fips140/sha256"
	"github.com/runZeroInc/excrypto/crypto/internal/fips140/sha3"
	"github.com/runZeroInc/excrypto/crypto/internal/fips140/sha512"
)

// Enabled reports whether FIPS 140-only mode is enabled, in which non-approved
// cryptography returns an error or panics.
var Enabled = godebug.New("fips140").Value() == "only"

func ApprovedHash(h hash.Hash) bool {
	switch h.(type) {
	case *sha256.Digest, *sha512.Digest, *sha3.Digest:
		return true
	default:
		return false
	}
}

func ApprovedRandomReader(r io.Reader) bool {
	_, ok := r.(drbg.DefaultReader)
	return ok
}
