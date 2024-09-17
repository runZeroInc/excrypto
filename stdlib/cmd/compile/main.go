// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/amd64"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/arm"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/arm64"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/base"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/gc"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/loong64"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/mips"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/mips64"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/ppc64"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/riscv64"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/s390x"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/ssagen"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/wasm"
	"github.com/runZeroInc/excrypto/stdlib/cmd/compile/internal/x86"
	"fmt"
	"github.com/runZeroInc/excrypto/stdlib/internal/buildcfg"
	"log"
	"os"
)

var archInits = map[string]func(*ssagen.ArchInfo){
	"386":      x86.Init,
	"amd64":    amd64.Init,
	"arm":      arm.Init,
	"arm64":    arm64.Init,
	"loong64":  loong64.Init,
	"mips":     mips.Init,
	"mipsle":   mips.Init,
	"mips64":   mips64.Init,
	"mips64le": mips64.Init,
	"ppc64":    ppc64.Init,
	"ppc64le":  ppc64.Init,
	"riscv64":  riscv64.Init,
	"s390x":    s390x.Init,
	"wasm":     wasm.Init,
}

func main() {
	// disable timestamps for reproducible output
	log.SetFlags(0)
	log.SetPrefix("compile: ")

	buildcfg.Check()
	archInit, ok := archInits[buildcfg.GOARCH]
	if !ok {
		fmt.Fprintf(os.Stderr, "compile: unknown architecture %q\n", buildcfg.GOARCH)
		os.Exit(2)
	}

	gc.Main(archInit)
	base.Exit(0)
}
