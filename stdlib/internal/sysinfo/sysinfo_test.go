// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sysinfo_test

import (
	. "github.com/runZeroInc/excrypto/stdlib/internal/sysinfo"
	"testing"
)

func TestCPUName(t *testing.T) {
	t.Logf("CPUName: %s", CPUName())
	t.Logf("osCPUInfoName: %s", XosCPUInfoName())
}
