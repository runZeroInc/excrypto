package ssh

import (
	"errors"
	"testing"
)

// TestUnauthClientConnRequestKeyExchange verifies that a client-requested
// rekey before userauth completes cleanly and leaves the connection usable
// for subsequent authentication.
func TestUnauthClientConnRequestKeyExchange(t *testing.T) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}

	serverConfig := &ServerConfig{
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			if conn.User() == "testuser" && string(password) == "tiger" {
				return nil, nil
			}
			return nil, errors.New("password rejected")
		},
	}
	serverConfig.AddHostKey(testSigners["rsa"])

	serverDone := make(chan error, 1)
	go func() {
		_, err := newServer(c1, serverConfig)
		serverDone <- err
	}()

	clientConfig := &ClientConfig{
		User:            "testuser",
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	uac, err := NewUnauthClientConn(c2, "pipe", clientConfig)
	if err != nil {
		t.Fatalf("NewUnauthClientConn: %v", err)
	}
	defer uac.c.Close()

	// Request a key re-exchange before any authentication.
	if err := uac.RequestKeyExchange(); err != nil {
		t.Fatalf("RequestKeyExchange: %v", err)
	}

	// The rekey is asynchronous; packets written while it runs are queued
	// and flushed once it completes. Authenticate over the rekeyed
	// transport to prove the connection is still usable.
	exts, err := uac.RequestUserAuth()
	if err != nil {
		t.Fatalf("RequestUserAuth after rekey: %v", err)
	}
	ares, _, err := uac.Authenticate(Password("tiger"), exts)
	if err != nil {
		t.Fatalf("Authenticate after rekey: %v", err)
	}
	if ares != AuthResultSuccess {
		t.Fatalf("Authenticate after rekey: got %v, want %v", ares, AuthResultSuccess)
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}
