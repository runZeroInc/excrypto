// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package unix provides minimal stubs for the few entropy syscalls that
// crypto/internal/sysrand uses. They read from /dev/urandom rather than the
// underlying syscall, since //go:linkname into syscall is not allowed from
// outside the standard library.
package unix

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	urMu sync.Mutex
	ur   *os.File

	randomSource         = readURandom
	fallbackRandomSource = readStdlibRandom

	fallbackWarned         atomic.Bool
	insecureFallbackWarned atomic.Bool
	insecureFallbackCount  atomic.Uint64
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

func readStdlibRandom(b []byte) error {
	_, err := cryptorand.Read(b)
	return err
}

func readWithFallback(b []byte) {
	if err := randomSource(b); err != nil {
		if fallbackWarned.CompareAndSwap(false, true) {
			_, _ = os.Stderr.WriteString("unix random source failed, using crypto/rand fallback: " + err.Error() + "\n")
		}
		if err := fallbackRandomSource(b); err == nil {
			return
		} else if insecureFallbackWarned.CompareAndSwap(false, true) {
			_, _ = os.Stderr.WriteString("crypto/rand fallback failed, using insecure fallback: " + err.Error() + "\n")
		}
		insecureFallbackRead(b)
	}
}

func insecureFallbackRead(b []byte) {
	var input [24]byte
	for len(b) > 0 {
		binary.LittleEndian.PutUint64(input[0:8], uint64(time.Now().UnixNano()))
		binary.LittleEndian.PutUint64(input[8:16], uint64(os.Getpid()))
		binary.LittleEndian.PutUint64(input[16:24], insecureFallbackCount.Add(1))
		block := sha256.Sum256(input[:])
		b = b[copy(b, block[:]):]
	}
}

// ARC4Random fills b with random bytes.
func ARC4Random(b []byte) {
	readWithFallback(b)
}

// Arandom fills b with random bytes.
func Arandom(b []byte) error {
	readWithFallback(b)
	return nil
}

// GetRandom fills b with random bytes.
func GetRandom(b []byte, _ int) (int, error) {
	readWithFallback(b)
	return len(b), nil
}

// GRND_NONBLOCK is the Linux flag indicating non-blocking entropy reads.
// Provided for source compatibility; ignored by readURandom.
const GRND_NONBLOCK = 0x0001
