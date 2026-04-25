package ssl2
// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ssl2 implements the obsolete SSL 2.0 protocol as described in
// Netscape's "The SSL Protocol" (Hickman, February 1995).
//
// SSL 2.0 was deprecated in 2011 by RFC 6176 and is cryptographically
// broken: it has no MAC over the handshake, conflates authentication and
// encryption keys, supports 40-bit "export" ciphers, and is vulnerable to
// (among other things) cipher-suite rollback and the DROWN attack
// (CVE-2016-0800). This package exists solely to enable security testing,
// inventory, and research of legacy systems that still negotiate SSL 2.0.
//
// It is NOT a general-purpose TLS stack and MUST NOT be used to protect
// any traffic. The implementation focuses on the wire format and on the
// scanning use case (drive a CLIENT-HELLO, parse the SERVER-HELLO,
// extract the offered cipher specs and X.509 certificate). Full bulk-data
// encryption is intentionally not wired up.
package ssl2
