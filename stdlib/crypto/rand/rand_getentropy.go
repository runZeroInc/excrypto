// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build openbsd || netbsd

package rand

import "github.com/runZeroInc/excrypto/stdlib/internal/syscall/unix"

func init() {
	// getentropy(2) returns a maximum of 256 bytes per call.
	altGetRandom = batched(unix.GetEntropy, 256)
}
