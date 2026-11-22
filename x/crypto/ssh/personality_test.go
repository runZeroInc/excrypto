package ssh

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestSNTRUP761RoundTrip(t *testing.T) {
	for i := 0; i < 3; i++ {
		pk, sk, err := sntrupKeyPair(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if len(pk) != sntrupPublicKeySize || len(sk) != sntrupSecretKeySize {
			t.Fatalf("sizes pk=%d sk=%d", len(pk), len(sk))
		}
		c, k, err := sntrupEncap(rand.Reader, pk)
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != sntrupCiphertextSize || len(k) != sntrupSharedKeySize {
			t.Fatalf("sizes c=%d k=%d", len(c), len(k))
		}
		if k2 := sntrupDecap(c, sk); !bytes.Equal(k, k2) {
			t.Fatal("decapsulated key differs")
		}
		c[5] ^= 1
		if k3 := sntrupDecap(c, sk); bytes.Equal(k, k3) {
			t.Fatal("tampered ciphertext gave the same key")
		}
	}
}

func TestPersonalityHandshake(t *testing.T) {
	p := &Personality{
		KeyExchanges:      []string{"mlkem-nope", KeyExchangeSNTRUP761X25519OpenSSH, KeyExchangeCurve25519, "ext-info-s", "kex-strict-s-v00@openssh.com"},
		HostKeyAlgorithms: []string{"rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"},
		Ciphers:           []string{CipherChaCha20Poly1305, CipherAES128CTR},
		MACs:              []string{"umac-64-etm@openssh.com", HMACSHA1ETM, HMACSHA256},
		Compressions:      []string{"none", "zlib@openssh.com"},
		ExtInfo:           []ExtInfoField{{"server-sig-algs", "ssh-ed25519,rsa-sha2-256"}, {"ping@openssh.com", "0"}},
		AuthMethods:       []string{"publickey", "password"},
	}
	for _, tc := range []struct{ kex, cipher, mac string }{
		{KeyExchangeSNTRUP761X25519OpenSSH, CipherChaCha20Poly1305, ""},
		{KeyExchangeCurve25519, CipherAES128CTR, HMACSHA1ETM},
	} {
		c1, c2, err := netPipe()
		if err != nil {
			t.Fatal(err)
		}
		srv := &ServerConfig{Config: Config{Personality: p}, PasswordCallback: func(ConnMetadata, []byte) (*Permissions, error) { return nil, errDeniedTest }}
		srv.AddHostKey(testSigners["ecdsa"])
		go func() { NewServerConn(c1, srv) }()
		cfg := &ClientConfig{User: "u", Auth: []AuthMethod{Password("x")}, HostKeyCallback: InsecureIgnoreHostKey(),
			Config:            Config{KeyExchanges: []string{tc.kex}, Ciphers: []string{tc.cipher}},
			HostKeyAlgorithms: []string{"ecdsa-sha2-nistp256"}}
		if tc.mac != "" {
			cfg.MACs = []string{tc.mac}
		}
		_, _, _, err = NewClientConn(c2, "x", cfg)
		if err == nil || !strings.Contains(err.Error(), "[none password]") {
			t.Fatalf("%s: want auth failure listing none password, got %v", tc.kex, err)
		}
		c2.Close()
	}
}

var errDeniedTest = errString("denied")

type errString string

func (e errString) Error() string { return string(e) }

// An agreement on an advertised but unimplemented MAC must be refused before
// a cipher is built from it.
func TestPersonalityUnimplementedMAC(t *testing.T) {
	if err := checkNegotiated(&NegotiatedAlgorithms{KeyExchange: KeyExchangeCurve25519,
		Read:  DirectionAlgorithms{Cipher: CipherAES128CTR, MAC: "hmac-nope", compression: "none"},
		Write: DirectionAlgorithms{Cipher: CipherAES128CTR, MAC: HMACSHA256, compression: "none"}}); err == nil {
		t.Fatal("hmac-nope accepted")
	}
	if err := checkNegotiated(&NegotiatedAlgorithms{KeyExchange: KeyExchangeSNTRUP761X25519,
		Read:  DirectionAlgorithms{Cipher: CipherChaCha20Poly1305, compression: "zlib@openssh.com"},
		Write: DirectionAlgorithms{Cipher: CipherAES128CTR, MAC: HMACSHA1ETM, compression: "none"}}); err != nil {
		t.Fatal(err)
	}
}

// UMAC and delayed compression run end to end: a login, then a session
// channel whose data crosses the compressed transport both ways.
func TestPersonalityUMACAndZlib(t *testing.T) {
	saved := supportedCompressions
	supportedCompressions = []string{compressionDelayed, compressionNone}
	defer func() { supportedCompressions = saved }()
	p := &Personality{
		KeyExchanges:      []string{KeyExchangeCurve25519},
		HostKeyAlgorithms: []string{"ecdsa-sha2-nistp256"},
		Ciphers:           []string{CipherAES128CTR},
		MACs:              []string{UMAC64ETM, UMAC128ETM, UMAC64, UMAC128},
		Compressions:      []string{compressionNone, compressionDelayed},
	}
	for _, mac := range []string{UMAC64ETM, UMAC128ETM, UMAC64, UMAC128} {
		for _, comp := range [][]string{{compressionDelayed}, {compressionNone}} {
			supportedCompressions = comp
			c1, c2, err := netPipe()
			if err != nil {
				t.Fatal(err)
			}
			srv := &ServerConfig{Config: Config{Personality: p}, PasswordCallback: func(ConnMetadata, []byte) (*Permissions, error) { return nil, nil }}
			srv.AddHostKey(testSigners["ecdsa"])
			done := make(chan error, 1)
			go func() {
				_, chans, reqs, err := NewServerConn(c1, srv)
				if err != nil {
					done <- err
					return
				}
				go DiscardRequests(reqs)
				nc := <-chans
				ch, creqs, err := nc.Accept()
				if err != nil {
					done <- err
					return
				}
				go DiscardRequests(creqs)
				buf := make([]byte, 70000)
				n, err := io.ReadFull(ch, buf)
				if err != nil {
					done <- err
					return
				}
				_, err = ch.Write(buf[:n])
				ch.CloseWrite()
				done <- err
			}()
			cfg := &ClientConfig{User: "u", Auth: []AuthMethod{Password("x")}, HostKeyCallback: InsecureIgnoreHostKey(),
				Config: Config{MACs: []string{mac}}, HostKeyAlgorithms: []string{"ecdsa-sha2-nistp256"}}
			conn, chans, reqs, err := NewClientConn(c2, "x", cfg)
			if err != nil {
				t.Fatalf("%s %v: %v", mac, comp, err)
			}
			tr := conn.(*connection).transport.(*handshakeTransport).conn.(*transport)
			if want := comp[0] == compressionDelayed; tr.writer.comp.active() != want || tr.reader.comp.active() != want {
				t.Fatalf("%s %v: compression active w=%v r=%v", mac, comp, tr.writer.comp.active(), tr.reader.comp.active())
			}
			client := NewClient(conn, chans, reqs)
			ch, _, err := client.OpenChannel("session", nil)
			if err != nil {
				t.Fatal(err)
			}
			msg := bytes.Repeat([]byte("paperdrake umac zlib "), 70000/21+1)[:70000]
			go ch.Write(msg)
			got, err := io.ReadAll(ch)
			if err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("%s %v: echo %d bytes, err %v", mac, comp, len(got), err)
			}
			if err := <-done; err != nil {
				t.Fatalf("%s %v server: %v", mac, comp, err)
			}
			client.Close()
		}
	}
}

// With an AuthPolicy, an unknown key gets USERAUTH_FAILURE to its query,
// failures count as the policy says, and MaxAuthTries ends with the policy's
// disconnect.
func TestPersonalityAuthPolicy(t *testing.T) {
	for _, disc := range []string{"Too many authentication failures", ""} {
		var calls []string
		var mu sync.Mutex
		p := &Personality{
			KeyExchanges: []string{KeyExchangeCurve25519}, HostKeyAlgorithms: []string{"ecdsa-sha2-nistp256"},
			Ciphers: []string{CipherAES128CTR}, MACs: []string{HMACSHA256},
			AuthPolicy: &AuthPolicy{Disconnect: disc, Failed: func(user, method string, query bool) bool {
				mu.Lock()
				calls = append(calls, fmt.Sprintf("%s/%v", method, query))
				mu.Unlock()
				return method != "none"
			}},
		}
		c1, c2, err := netPipe()
		if err != nil {
			t.Fatal(err)
		}
		srv := &ServerConfig{Config: Config{Personality: p}, MaxAuthTries: 3,
			PublicKeyCallback: func(ConnMetadata, PublicKey) (*Permissions, error) { return nil, errDeniedTest },
			PasswordCallback:  func(ConnMetadata, []byte) (*Permissions, error) { return nil, errDeniedTest }}
		srv.AddHostKey(testSigners["ecdsa"])
		go NewServerConn(c1, srv)
		signed := 0
		cfg := &ClientConfig{User: "u", HostKeyCallback: InsecureIgnoreHostKey(), HostKeyAlgorithms: []string{"ecdsa-sha2-nistp256"},
			Auth: []AuthMethod{PublicKeysCallback(func() ([]Signer, error) {
				return []Signer{&countingSigner{testSigners["rsa"], &signed}, &countingSigner{testSigners["ed25519"], &signed}}, nil
			}), RetryableAuthMethod(Password("x"), 5)}}
		_, _, _, err = NewClientConn(c2, "x", cfg)
		c2.Close()
		if err == nil {
			t.Fatal("login succeeded")
		}
		if signed != 0 {
			t.Errorf("client signed %d times: a query was approved", signed)
		}
		if disc != "" && !strings.Contains(err.Error(), disc) {
			t.Errorf("want disconnect %q, got %v", disc, err)
		}
		if disc == "" && strings.Contains(err.Error(), "too many") {
			t.Errorf("silent close sent a disconnect: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if want := "none/false publickey/true publickey/true"; !strings.HasPrefix(strings.Join(calls, " "), want) || len(calls) != 4 {
			t.Errorf("policy calls %v", calls)
		}
	}
}

type countingSigner struct {
	Signer
	n *int
}

func (s *countingSigner) Sign(r io.Reader, data []byte) (*Signature, error) {
	*s.n++
	return s.Signer.Sign(r, data)
}
