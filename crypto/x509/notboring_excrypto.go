// Copyright 2026 The excrypto Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

// boringAllowCert is the BoringSSL FIPS 140 mode hook used by upstream Go's
// x509 verifier. excrypto removes the boring backend (see crypto/internal/boring),
// so the hook always permits the certificate.
func boringAllowCert(*Certificate) bool { return true }
