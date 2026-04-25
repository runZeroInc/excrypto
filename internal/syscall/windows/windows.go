// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

// Package windows provides minimal Windows syscall stubs needed by
// crypto/internal/sysrand and crypto/internal/fips140deps/time.
package windows

import (
	"syscall"
	"unsafe"
)

var (
	modbcryptprimitives = syscall.NewLazyDLL("bcryptprimitives.dll")
	modkernel32         = syscall.NewLazyDLL("kernel32.dll")

	procProcessPrng             = modbcryptprimitives.NewProc("ProcessPrng")
	procQueryPerformanceCounter = modkernel32.NewProc("QueryPerformanceCounter")
)

// ProcessPrng fills b with cryptographically random bytes from the Windows
// per-process PRNG.
func ProcessPrng(b []byte) error {
	var p *byte
	if len(b) > 0 {
		p = &b[0]
	}
	r1, _, e := syscall.SyscallN(procProcessPrng.Addr(), uintptr(unsafe.Pointer(p)), uintptr(len(b)))
	if r1 == 0 {
		if e != 0 {
			return e
		}
		return syscall.EINVAL
	}
	return nil
}

// QueryPerformanceCounter returns the current value of the high-resolution
// performance counter.
func QueryPerformanceCounter() int64 {
	var c int64
	syscall.SyscallN(procQueryPerformanceCounter.Addr(), uintptr(unsafe.Pointer(&c)))
	return c
}
