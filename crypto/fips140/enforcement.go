// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fips140

import (
	_ "unsafe" // for linkname

	"github.com/runZeroInc/excrypto/internal/godebug"
)

// WithoutEnforcement disables strict FIPS 140-3 enforcement while executing f.
// Calling WithoutEnforcement without strict enforcement enabled
// (GODEBUG=fips140=only is not set or already inside of a call to
// WithoutEnforcement) is a no-op.
//
// WithoutEnforcement is inherited by any goroutines spawned while executing f.
//
// As this disables enforcement, it should be applied carefully to tightly
// scoped functions.
func WithoutEnforcement(f func()) {
	if !Enabled() || !Enforced() {
		f()
		return
	}
	setBypass()
	defer unsetBypass()
	f()
}

var enabled = godebug.New("fips140").Value() == "only"

// Enforced indicates if strict FIPS 140-3 enforcement is enabled. Strict
// enforcement is enabled when a program is run with GODEBUG=fips140=only and
// enforcement has not been disabled by a call to [WithoutEnforcement].
func Enforced() bool {
	return enabled && !isBypassed()
}

// In stdlib these are linkname'd to runtime so the bypass is per-goroutine.
// excrypto operates outside the runtime; provide a process-global fallback.
var globalBypass uint32

func setBypass()       { globalBypass = 1 }
func isBypassed() bool { return globalBypass == 1 }
func unsetBypass()     { globalBypass = 0 }
