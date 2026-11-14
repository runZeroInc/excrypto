// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fips140

import (
	"sync"
	"testing"
)

func TestIndicatorTransitions(t *testing.T) {
	ResetServiceIndicator()
	if ServiceIndicator() {
		t.Fatal("indicator is true after a reset")
	}
	RecordApproved()
	if !ServiceIndicator() {
		t.Fatal("indicator is false after an approved service")
	}
	RecordNonApproved()
	RecordApproved()
	if ServiceIndicator() {
		t.Fatal("an approved service overrode a non-approved one")
	}
	ResetServiceIndicator()
}

// TestIndicatorConcurrentUse fails under the race detector when indicator access is unsynchronized.
func TestIndicatorConcurrentUse(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				if i%2 == 0 {
					RecordApproved()
				} else {
					RecordNonApproved()
				}
				_ = ServiceIndicator()
			}
		}()
	}
	wg.Wait()
	ResetServiceIndicator()
}
