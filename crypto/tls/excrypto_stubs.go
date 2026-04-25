// Copyright 2026 The excrypto Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Minimal compatibility stubs to bridge upstream go1.26.2 tls/ files with
// excrypto's overall layout. Keep this file SMALL; prefer fixing real types.

package tls

// needFIPS reports whether the FIPS 140-3 mode is required. excrypto disables
// FIPS-only restrictions to preserve weak-cipher and lax-parsing behavior.
func needFIPS() bool { return false }
