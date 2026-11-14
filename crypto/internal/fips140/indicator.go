// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fips140

import "sync/atomic"

// The service indicator lets users of the module query whether invoked services
// are approved. Three states are stored in a per-goroutine value by the
// runtime. The indicator starts at indicatorUnset after a reset. Invoking an
// approved service transitions to indicatorTrue. Invoking a non-approved
// service transitions to indicatorFalse, and it can't leave that state until a
// reset. The idea is that functions can "delegate" checks to inner functions,
// and if there's anything non-approved in the stack, the final result is
// negative. Finally, we expose indicatorUnset as negative to the user, so that
// we don't need to explicitly annotate fully non-approved services.

// In stdlib the indicator state is per-goroutine and comes from the runtime.
// excrypto operates outside the stdlib runtime and keeps one process-global
// indicator. Access is atomic, so concurrent use of the module is race-free;
// the value itself is only meaningful when a single goroutine uses the module
// between ResetServiceIndicator and ServiceIndicator.
var globalIndicator atomic.Uint32

func getIndicator() uint8  { return uint8(globalIndicator.Load()) }
func setIndicator(v uint8) { globalIndicator.Store(uint32(v)) }

const (
	indicatorUnset uint8 = iota
	indicatorFalse
	indicatorTrue
)

// ResetServiceIndicator clears the service indicator for the running goroutine.
func ResetServiceIndicator() {
	setIndicator(indicatorUnset)
}

// ServiceIndicator returns true if and only if all services invoked by this
// goroutine since the last ResetServiceIndicator call are approved.
//
// If ResetServiceIndicator was not called before by this goroutine, its return
// value is undefined.
func ServiceIndicator() bool {
	return getIndicator() == indicatorTrue
}

// RecordApproved is an internal function that records the use of an approved
// service. It does not override RecordNonApproved calls in the same span.
//
// It should be called by exposed functions that perform a whole cryptographic
// alrgorithm (e.g. by Sum, not by New, unless a cryptographic Instantiate
// algorithm is performed) and should be called after any checks that may cause
// the function to error out or panic.
func RecordApproved() {
	globalIndicator.CompareAndSwap(uint32(indicatorUnset), uint32(indicatorTrue))
}

// RecordNonApproved is an internal function that records the use of a
// non-approved service. It overrides any RecordApproved calls in the same span.
func RecordNonApproved() {
	setIndicator(indicatorFalse)
}
