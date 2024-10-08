// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

package sha512

import "github.com/runZeroInc/excrypto/internal/cpu"

var useAsm = cpu.S390X.HasSHA512
