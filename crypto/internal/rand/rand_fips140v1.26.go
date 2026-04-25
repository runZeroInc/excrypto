// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !fips140v1.0

package rand

import (
	"io"

	"github.com/runZeroInc/excrypto/crypto/internal/fips140/drbg"
)

func fips140SetTestingReader(r io.Reader) {
	drbg.SetTestingReader(r)
}
