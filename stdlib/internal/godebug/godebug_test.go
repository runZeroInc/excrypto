// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package godebug_test

import (
	"os"
	"testing"

	"github.com/runZeroInc/excrypto/stdlib/internal/godebug"
	. "github.com/runZeroInc/excrypto/stdlib/internal/godebug"
	"github.com/runZeroInc/excrypto/stdlib/internal/testenv"
)

func TestGet(t *testing.T) {
	foo := New("#foo")
	tests := []struct {
		godebug string
		setting *Setting
		want    string
	}{
		{"", New("#"), ""},
		{"", foo, ""},
		{"foo=bar", foo, "bar"},
		{"foo=bar,after=x", foo, "bar"},
		{"before=x,foo=bar,after=x", foo, "bar"},
		{"before=x,foo=bar", foo, "bar"},
		{",,,foo=bar,,,", foo, "bar"},
		{"foodecoy=wrong,foo=bar", foo, "bar"},
		{"foo=", foo, ""},
		{"foo", foo, ""},
		{",foo", foo, ""},
		{"foo=bar,baz", New("#loooooooong"), ""},
	}
	for _, tt := range tests {
		godebug.SetEnv("GODEBUG", tt.godebug)
		got := tt.setting.Value()
		if got != tt.want {
			t.Errorf("get(%q, %q) = %q; want %q", tt.godebug, tt.setting.Name(), got, tt.want)
		}
	}
}

// TestPanicNilRace checks for a race in the runtime caused by use of runtime
// atomics (not visible to usual race detection) to install the counter for
// non-default panic(nil) semantics.  For #64649.
func TestPanicNilRace(t *testing.T) {
	if os.Getenv("GODEBUG") != "panicnil=1" {
		cmd := testenv.CleanCmdEnv(testenv.Command(t, os.Args[0], "-test.run=^TestPanicNilRace$", "-test.v", "-test.parallel=2", "-test.count=1"))
		cmd.Env = append(cmd.Env, "GODEBUG=panicnil=1")
		out, err := cmd.CombinedOutput()
		t.Logf("output:\n%s", out)

		if err != nil {
			t.Errorf("Was not expecting a crash")
		}
		return
	}

	test := func(t *testing.T) {
		t.Parallel()
		defer func() {
			recover()
		}()
		panic(nil)
	}
	t.Run("One", test)
	t.Run("Two", test)
}
