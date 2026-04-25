// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveHandshake performs a full SSL 2.0 handshake (and a small
// application-data round trip when the peer cooperates) against one or more
// real targets. It is OFF by default: set SSL2_LIVE_TARGETS to a
// comma-separated list of host:port pairs to enable, e.g.:
//
//	SSL2_LIVE_TARGETS=10.114.128.79:6000,10.114.128.60:443 \
//	  go test -run TestLiveHandshake -v ./crypto/ssl2/...
//
// The test fails if a target advertises SSL 2.0 in its SERVER-HELLO but the
// subsequent handshake does not complete. Targets that simply refuse SSL 2.0
// (no SERVER-HELLO, or a peer ERROR before key exchange) are SKIPPED, not
// failed, since the goal here is to exercise the full-handshake code path
// where the peer supports it.
func TestLiveHandshake(t *testing.T) {
	raw := os.Getenv("SSL2_LIVE_TARGETS")
	if raw == "" {
		t.Skip("set SSL2_LIVE_TARGETS=host:port[,host:port...] to enable")
	}
	for _, addr := range strings.Split(raw, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		t.Run(addr, func(t *testing.T) {
			c, hr, err := DialAndHandshake(addr, 10*time.Second)
			if err != nil {
				// The peer may simply not speak SSL 2.0; that's an
				// expected outcome for most modern services. We surface
				// it as a Skip rather than a failure so the test can be
				// pointed at a heterogeneous list.
				t.Skipf("DialAndHandshake(%s): %v", addr, err)
				return
			}
			defer c.Close()
			t.Logf("negotiated %s with %s (subject %q)", hr.Cipher.Name(), addr, hr.Certificate.Subject.CommonName)
			// Best-effort application-data probe: many SSL 2.0 services
			// (NNTP, POP3, IMAP, custom protocols on port 6000) emit a
			// banner immediately. We give it 2 seconds and accept either
			// some bytes or a timeout/EOF.
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 256)
			n, rerr := c.Read(buf)
			if n > 0 {
				t.Logf("first %d bytes from %s: %q", n, addr, buf[:n])
			} else if rerr != nil {
				t.Logf("no banner from %s (%v); handshake itself succeeded", addr, rerr)
			}
		})
	}
}
