// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package unix provides minimal stubs for the few entropy syscalls that
// crypto/internal/sysrand uses. They read from /dev/urandom rather than the
// underlying syscall, since //go:linkname into syscall is not allowed from
// outside the standard library.
package unix

import (
	"io"
	"os"
	"sync"
)

var (
	urMu sync.Mutex
	ur   *os.File
)

func readURandom(b []byte) error {
	urMu.Lock()
	defer urMu.Unlock()
	if ur == nil {
		f, err := os.Open("/dev/urandom")
		if err != nil {
			return err
		}
		ur = f
	}
	_, err := io.ReadFull(ur, b)
	return err
}

// ARC4Random fills b with cryptographically random bytes.
func ARC4Random(b []byte) {
	if err := readURandom(b); err != nil {
		panic("unix.ARC4Random: " + err.Error())
	}
}

// Arandom fills b with cryptographically random bytes.
func Arandom(b []byte) error { return readURandom(b) }

// GetRandom fills b with cryptographically random bytes.
func GetRandom(b []byte, _ int) (int, error) {
	if err := readURandom(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// GRND_NONBLOCK is the Linux flag indicating non-blocking entropy reads.
// Provided for source compatibility; ignored by readURandom.
const GRND_NONBLOCK = 0x0001
