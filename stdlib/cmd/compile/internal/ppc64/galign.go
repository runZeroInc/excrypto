// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ppc64

import (
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/ssagen"
	"github.com/runZeroInc/excrypto/stdlib/cmd/internal/obj/ppc64"
	"github.com/runZeroInc/excrypto/stdlib/internal/buildcfg"
)

func Init(arch *ssagen.ArchInfo) {
	arch.LinkArch = &ppc64.Linkppc64
	if buildcfg.GOARCH == "ppc64le" {
		arch.LinkArch = &ppc64.Linkppc64le
	}
	arch.REGSP = ppc64.REGSP
	arch.MAXWIDTH = 1 << 50

	arch.ZeroRange = zerorange
	arch.Ginsnop = ginsnop

	arch.SSAMarkMoves = ssaMarkMoves
	arch.SSAGenValue = ssaGenValue
	arch.SSAGenBlock = ssaGenBlock
	arch.LoadRegResult = loadRegResult
	arch.SpillArgReg = spillArgReg
}
