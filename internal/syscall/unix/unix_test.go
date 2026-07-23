// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unix

import (
	"bytes"
	"errors"
	"testing"
)

func TestRandomFallbackUsesStdlibSource(t *testing.T) {
	oldRandomSource := randomSource
	oldFallbackRandomSource := fallbackRandomSource
	randomSource = func([]byte) error { return errors.New("forced failure") }
	fallbackRandomSource = func(b []byte) error {
		for i := range b {
			b[i] = 0xa5
		}
		return nil
	}
	defer func() {
		randomSource = oldRandomSource
		fallbackRandomSource = oldFallbackRandomSource
	}()

	want := bytes.Repeat([]byte{0xa5}, 64)

	b := make([]byte, 64)
	ARC4Random(b)
	if !bytes.Equal(b, want) {
		t.Fatal("ARC4Random did not use fallback random source")
	}

	b = make([]byte, 64)
	if err := Arandom(b); err != nil {
		t.Fatalf("Arandom returned error from fallback: %v", err)
	}
	if !bytes.Equal(b, want) {
		t.Fatal("Arandom did not use fallback random source")
	}

	b = make([]byte, 64)
	n, err := GetRandom(b, 0)
	if err != nil {
		t.Fatalf("GetRandom returned error from fallback: %v", err)
	}
	if n != len(b) {
		t.Fatalf("GetRandom returned %d bytes, want %d", n, len(b))
	}
	if !bytes.Equal(b, want) {
		t.Fatal("GetRandom did not use fallback random source")
	}
}

func TestRandomFallbackDoesNotPanicIfAllEntropyFails(t *testing.T) {
	oldRandomSource := randomSource
	oldFallbackRandomSource := fallbackRandomSource
	randomSource = func([]byte) error { return errors.New("forced failure") }
	fallbackRandomSource = func([]byte) error { return errors.New("forced fallback failure") }
	defer func() {
		randomSource = oldRandomSource
		fallbackRandomSource = oldFallbackRandomSource
	}()

	b := make([]byte, 64)
	ARC4Random(b)
	if bytes.Equal(b, make([]byte, len(b))) {
		t.Fatal("last-resort fallback returned all zero bytes")
	}
}
