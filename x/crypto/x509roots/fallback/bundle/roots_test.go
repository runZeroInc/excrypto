// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bundle

import (
	"testing"

	"github.com/runZeroInc/excrypto/crypto/x509"
)

func TestRootsCanBeParsed(t *testing.T) {
	for root := range Roots() {
		if _, err := x509.ParseCertificate(root.Certificate); err != nil {
			t.Fatalf("Could not parse root certificate: %v", err)
		}
	}
}
