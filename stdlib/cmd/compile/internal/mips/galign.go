// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mips

import (
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/ssa"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/ssagen"
	"github.com/runZeroInc/excrypto/stdlib/cmd/internal/obj/mips"
	"github.com/runZeroInc/excrypto/stdlib/internal/buildcfg"
)

func Init(arch *ssagen.ArchInfo) {
	arch.LinkArch = &mips.Linkmips
	if buildcfg.GOARCH == "mipsle" {
		arch.LinkArch = &mips.Linkmipsle
	}
	arch.REGSP = mips.REGSP
	arch.MAXWIDTH = (1 << 31) - 1
	arch.SoftFloat = (buildcfg.GOMIPS == "softfloat")
	arch.ZeroRange = zerorange
	arch.Ginsnop = ginsnop
	arch.SSAMarkMoves = func(s *ssagen.State, b *ssa.Block) {}
	arch.SSAGenValue = ssaGenValue
	arch.SSAGenBlock = ssaGenBlock
}
