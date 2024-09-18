package tests

import (
	"testing"

	"github.com/runZeroInc/excrypto/stdlib/crypto/tls"
)

func TestBasicTLS(t *testing.T) {
	c, err := tls.Dial("tcp", "google.com:443", &tls.Config{})
	if err != nil {
		t.Fatalf("tls connection failed: %s", err)
	}
	c.Close()
}
