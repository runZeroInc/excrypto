// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm64

import (
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/ssa"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/ssagen"
	"github.com/runZeroInc/excrypto/stdlib/cmd/internal/obj/arm64"
)

func Init(arch *ssagen.ArchInfo) {
	arch.LinkArch = &arm64.Linkarm64
	arch.REGSP = arm64.REGSP
	arch.MAXWIDTH = 1 << 50

	arch.PadFrame = padframe
	arch.ZeroRange = zerorange
	arch.Ginsnop = ginsnop

	arch.SSAMarkMoves = func(s *ssagen.State, b *ssa.Block) {}
	arch.SSAGenValue = ssaGenValue
	arch.SSAGenBlock = ssaGenBlock
	arch.LoadRegResult = loadRegResult
	arch.SpillArgReg = spillArgReg
}
