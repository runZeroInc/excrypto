// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fipstest

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/runZeroInc/excrypto/crypto/internal/cryptotest"
	. "github.com/runZeroInc/excrypto/crypto/internal/fips140/check"
	"github.com/runZeroInc/excrypto/internal/godebug"
	"github.com/runZeroInc/excrypto/internal/testenv"
)

func TestIntegrityCheck(t *testing.T) {
	if Verified {
		t.Logf("verified")
		return
	}

	if godebug.New("fips140").Value() == "on" {
		t.Fatalf("GODEBUG=fips140=on but verification did not run")
	}

	cryptotest.RerunWithFIPS140Enabled(t)
}

func TestIntegrityCheckFailure(t *testing.T) {
	moduleStatus(t)
	cryptotest.MustSupportFIPS140(t)

	bin, err := os.ReadFile(testenv.Executable(t))
	if err != nil {
		t.Fatal(err)
	}

	// Replace the expected module checksum with a different value.
	bin = bytes.ReplaceAll(bin, Linkinfo.Sum[:], bytes.Repeat([]byte("X"), len(Linkinfo.Sum)))

	binPath := filepath.Join(t.TempDir(), "fips140test.exe")
	if err := os.WriteFile(binPath, bin, 0o755); err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS == "darwin" {
		// Regenerate the macOS ad-hoc code signature.
		cmd := testenv.Command(t, "codesign", "-s", "-", "-f", binPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("codesign failed: %v\n%s", err, out)
		}
	}

	t.Logf("running modified binary...")
	cmd := testenv.Command(t, binPath, "-test.v", "-test.run=^TestIntegrityCheck$")
	cmd.Env = append(cmd.Environ(), "GODEBUG=fips140=on")
	out, err := cmd.CombinedOutput()
	t.Logf("running with GODEBUG=fips140=on:\n%s", out)
	if err == nil {
		t.Errorf("modified binary did not fail as expected")
	}
	if !bytes.Contains(out, []byte("fips140: verification mismatch")) {
		t.Errorf("modified binary did not fail with expected message")
	}
	if bytes.Contains(out, []byte("verified")) {
		t.Errorf("modified binary did not exit")
	}
}

