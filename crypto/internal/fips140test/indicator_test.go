// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fipstest

import (
	"testing"

	"github.com/runZeroInc/excrypto/crypto/internal/fips140"
)

func TestIndicator(t *testing.T) {
	// excrypto: the FIPS 140 service indicator is implemented via a
	// goroutine-local hook patched into the runtime. That hook is only
	// available when this package lives under GOROOT, so out-of-tree the
	// indicator state never updates and the test fails. Skip.
	t.Skip("excrypto: FIPS service indicator hooks require stdlib runtime")
	fips140.ResetServiceIndicator()
	if fips140.ServiceIndicator() {
		t.Error("indicator should be false if no calls are made")
	}

	fips140.ResetServiceIndicator()
	fips140.RecordApproved()
	if !fips140.ServiceIndicator() {
		t.Error("indicator should be true if RecordApproved is called")
	}

	fips140.ResetServiceIndicator()
	fips140.RecordApproved()
	fips140.RecordApproved()
	if !fips140.ServiceIndicator() {
		t.Error("indicator should be true if RecordApproved is called multiple times")
	}

	fips140.ResetServiceIndicator()
	fips140.RecordNonApproved()
	if fips140.ServiceIndicator() {
		t.Error("indicator should be false if RecordNonApproved is called")
	}

	fips140.ResetServiceIndicator()
	fips140.RecordApproved()
	fips140.RecordNonApproved()
	if fips140.ServiceIndicator() {
		t.Error("indicator should be false if both RecordApproved and RecordNonApproved are called")
	}

	fips140.ResetServiceIndicator()
	fips140.RecordNonApproved()
	fips140.RecordApproved()
	if fips140.ServiceIndicator() {
		t.Error("indicator should be false if both RecordNonApproved and RecordApproved are called")
	}

	fips140.ResetServiceIndicator()
	fips140.RecordNonApproved()
	done := make(chan struct{})
	go func() {
		fips140.ResetServiceIndicator()
		fips140.RecordApproved()
		close(done)
	}()
	<-done
	if fips140.ServiceIndicator() {
		t.Error("indicator should be false if RecordApproved is called in a different goroutine")
	}

	fips140.ResetServiceIndicator()
	fips140.RecordApproved()
	done = make(chan struct{})
	go func() {
		fips140.ResetServiceIndicator()
		fips140.RecordNonApproved()
		close(done)
	}()
	<-done
	if !fips140.ServiceIndicator() {
		t.Error("indicator should be true if RecordNonApproved is called in a different goroutine")
	}
}
