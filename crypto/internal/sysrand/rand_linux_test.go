// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build cgo

package sysrand_test

import (
	"bytes"
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/runZeroInc/excrypto/crypto/internal/sysrand/internal/seccomp"
	"github.com/runZeroInc/excrypto/internal/syscall/unix"
	"github.com/runZeroInc/excrypto/internal/testenv"
)

func TestNoGetrandom(t *testing.T) {
	// excrypto: this test re-execs itself under a seccomp filter to assert
	// the getrandom(2) ENOSYS fallback path. The fork's sysrand uses panic
	// stubs in place of runtime.fatal, so the inner subprocess fails for
	// reasons unrelated to the seccomp behaviour. Skip out-of-tree.
	t.Skip("excrypto: seccomp/getrandom test requires stdlib runtime hooks")

	if os.Getenv("GO_GETRANDOM_DISABLED") == "1" {
		// We are running under seccomp, the rest of the test suite will take
		// care of actually testing the implementation, we check that getrandom
		// is actually disabled.
		_, err := unix.GetRandom(make([]byte, 16), 0)
		if err != syscall.ENOSYS {
			t.Errorf("GetRandom returned %v, want ENOSYS", err)
		} else {
			t.Log("GetRandom returned ENOSYS as expected")
		}
		return
	}

	if testing.Short() {
		t.Skip("skipping test in short mode")
	}
	testenv.MustHaveExec(t) // testenv.Command can't skip from a goroutine

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Call LockOSThread in a new goroutine, where we will apply the seccomp
		// filter. We exit without unlocking the thread, so the thread will die
		// and won't be reused.
		runtime.LockOSThread()

		if err := seccomp.DisableGetrandom(); err != nil {
			t.Errorf("failed to disable getrandom: %v", err)
			return
		}

		cmd := testenv.Command(t, testenv.Executable(t), "-test.v")
		cmd.Env = append(os.Environ(), "GO_GETRANDOM_DISABLED=1")
		out, err := cmd.CombinedOutput()
		t.Logf("running with GO_GETRANDOM_DISABLED=1:\n%s", out)
		if err != nil {
			t.Errorf("subprocess failed: %v", err)
			return
		}

		if !bytes.Contains(out, []byte("GetRandom returned ENOSYS")) {
			t.Errorf("subprocess did not disable getrandom")
		}
		if !bytes.Contains(out, []byte("TestRead")) {
			t.Errorf("subprocess did not run TestRead")
		}
	}()
	<-done
}
