// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fips140hash

import (
	"hash"
	_ "unsafe"
)

// Unwrap returns h, or a crypto/internal/fips140 inner implementation of h.
//
// The return value can be type asserted to one of
// [crypto/internal/fips140/sha256.Digest],
// [crypto/internal/fips140/sha512.Digest], or
// [crypto/internal/fips140/sha3.Digest] if it is a FIPS 140-3 approved hash.
func Unwrap(h hash.Hash) hash.Hash {
	return h
}

// UnwrapNew returns a function that calls newHash and applies [Unwrap] to the
// return value.
func UnwrapNew[Hash hash.Hash](newHash func() Hash) func() hash.Hash {
	return func() hash.Hash { return Unwrap(newHash()) }
}
