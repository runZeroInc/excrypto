// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import "fmt"

// mustNewOIDFromInts is a tiny test helper that mirrors the upstream stdlib
// helper of the same name. It panics if OIDFromInts returns an error.
func mustNewOIDFromInts(ints []uint64) OID {
	oid, err := OIDFromInts(ints)
	if err != nil {
		panic(fmt.Sprintf("OIDFromInts(%v) unexpected error: %v", ints, err))
	}
	return oid
}

// anyPolicyOID is the OID for the special anyPolicy certificate policy.
var anyPolicyOID = mustNewOIDFromInts([]uint64{2, 5, 29, 32, 0})
