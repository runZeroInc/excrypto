package ssh

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/runZeroInc/excrypto/crypto"
	"github.com/runZeroInc/excrypto/crypto/dsa"
	"github.com/runZeroInc/excrypto/crypto/rc4"
)

var legacyTestMACs = []string{HMACSHA1, InsecureHMACSHA196, HMACSHA1ETM, HMACSHA256ETM}

// Every legacy cipher with every legacy MAC, and every legacy MAC with a CBC
// and a CTR cipher, round-trips several packets in a row (so CBC chaining and
// keystream position carry across packets).
func TestLegacyPacketRoundTrip(t *testing.T) {
	ciphers, macs := legacyNames()
	ciphers = append(ciphers, InsecureCipherAES128CBC, InsecureCipherTripleDESCBC, InsecureCipherRC4, InsecureCipherRC4128, InsecureCipherRC4256)
	kr := &kexResult{Hash: crypto.SHA1, K: []byte{1}, H: []byte{2}, SessionID: []byte{3}}
	for _, c := range ciphers {
		for _, m := range append(slices.Clone(macs), legacyTestMACs...) {
			algs := DirectionAlgorithms{Cipher: c, MAC: m, compression: compressionNone, legacy: true}
			w, err := newPacketCipher(clientKeys, algs, kr)
			if err != nil {
				t.Fatalf("%s/%s: %v", c, m, err)
			}
			r, _ := newPacketCipher(clientKeys, algs, kr)
			buf := &bytes.Buffer{}
			var want [][]byte
			for i, n := range []int{1, 7, 16, 100, 1000, 35000} {
				p := make([]byte, n)
				rand.Read(p)
				want = append(want, slices.Clone(p))
				if err := w.writeCipherPacket(uint32(i), buf, rand.Reader, p); err != nil {
					t.Fatalf("%s/%s write: %v", c, m, err)
				}
			}
			for i := range want {
				got, err := r.readCipherPacket(uint32(i), buf)
				if err != nil || !bytes.Equal(got, want[i]) {
					t.Fatalf("%s/%s packet %d: err %v, equal %v", c, m, i, err, bytes.Equal(got, want[i]))
				}
			}
		}
	}
}

// Packets are padded to the cipher's block size, as OpenSSH and dropbear do.
func TestLegacyPadding(t *testing.T) {
	kr := &kexResult{Hash: crypto.SHA1, K: []byte{1}, H: []byte{2}, SessionID: []byte{3}}
	for c, bs := range map[string]int{CipherBlowfishCBC: 8, CipherCAST128CBC: 8, InsecureCipherTripleDESCBC: 8, CipherTripleDESCTR: 8,
		CipherAES256CBC: 16, CipherTwofishCBC: 16, CipherTwofish256CTR: 16, InsecureCipherRC4256: 8, CipherNone: 8} {
		for _, m := range []string{HMACMD5, HMACMD5ETM, MACNone} {
			algs := DirectionAlgorithms{Cipher: c, MAC: m, compression: compressionNone, legacy: true}
			w, _ := newPacketCipher(clientKeys, algs, kr)
			mm := macModeFor(m, true)
			macLen := 0
			if h := mm.new(make([]byte, mm.keySize)); h != nil {
				macLen = h.Size()
			}
			for n := 1; n < 40; n++ {
				buf := &bytes.Buffer{}
				w.writeCipherPacket(0, buf, rand.Reader, make([]byte, n))
				enc := buf.Len() - macLen
				if mm.etm {
					enc -= 4
				}
				if enc%bs != 0 {
					t.Fatalf("%s/%s payload %d: encrypted part %d not a multiple of %d", c, m, n, enc, bs)
				}
				if pad := buf.Len() - macLen - 5 - n; pad < 4 || pad >= 4+bs {
					t.Fatalf("%s/%s payload %d: padding %d", c, m, n, pad)
				}
			}
		}
	}
}

// RFC 2104 / RFC 2286 test case 1 and RFC 4345's 1536-byte discard.
func TestLegacyVectors(t *testing.T) {
	for _, tc := range []struct{ mac, key, want string }{
		{HMACMD5, strings.Repeat("0b", 16), "9294727a3638bb1c13f48ef8158bfc9d"},
		{HMACMD596, strings.Repeat("0b", 16), "9294727a3638bb1c13f48ef8"},
		{HMACRIPEMD160, strings.Repeat("0b", 20), "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668"},
		{HMACRIPEMD160OpenSSH, strings.Repeat("0b", 20), "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668"},
		{HMACSHA196ETM, strings.Repeat("0b", 20), "b617318655057264e28bc0b6"},
		{HMACSHA256_96, strings.Repeat("0b", 20), "b0344c61d8db38535ca8afce"},
		{HMACSHA512_96, strings.Repeat("0b", 20), "87aa7cdea5ef619d4ff0b4241"[:24]},
	} {
		key, _ := hex.DecodeString(tc.key)
		h := macModeFor(tc.mac, true).new(key)
		h.Write([]byte("Hi There"))
		if got := hex.EncodeToString(h.Sum(nil)); got != tc.want {
			t.Errorf("%s: got %s want %s", tc.mac, got, tc.want)
		}
	}
	key := bytes.Repeat([]byte{7}, 32)
	for name, skip := range map[string]int{InsecureCipherRC4: 0, InsecureCipherRC4128: 1536, InsecureCipherRC4256: 1536} {
		mode := cipherModeFor(name, false)
		pc, _ := mode.create(key[:mode.keySize], nil, nil, DirectionAlgorithms{Cipher: name, MAC: MACNone, legacy: true})
		ref, _ := rc4.NewCipher(key[:mode.keySize])
		ks := make([]byte, skip+64)
		ref.XORKeyStream(ks, ks)
		got := make([]byte, 64)
		pc.(*streamPacketCipher).cipher.XORKeyStream(got, got)
		if !bytes.Equal(got, ks[skip:]) {
			t.Errorf("%s: keystream does not start at byte %d", name, skip)
		}
	}
}

// A legacy name is never offered or accepted without a Personality: not in
// any default or listed set, dropped from an explicit Config, and refused by
// a default server.
func TestLegacyNeverDefault(t *testing.T) {
	ciphers, macs := legacyNames()
	legacy := append(slices.Clone(ciphers), macs...)
	sup, ins := SupportedAlgorithms(), InsecureAlgorithms()
	for _, l := range [][]string{defaultCiphers, defaultMACs, defaultKexAlgos, defaultHostKeyAlgos, supportedCiphers, supportedMACs,
		insecureCiphers, insecureMACs, sup.Ciphers, sup.MACs, ins.Ciphers, ins.MACs} {
		for _, n := range legacy {
			if slices.Contains(l, n) {
				t.Errorf("%s is in a default or listed set", n)
			}
		}
	}
	for _, n := range ciphers {
		if cipherModes[n] != nil || cipherModeFor(n, false) != nil {
			t.Errorf("cipher %s reachable without a personality", n)
		}
	}
	for _, n := range macs {
		if macModes[n] != nil || macModeFor(n, false) != nil {
			t.Errorf("MAC %s reachable without a personality", n)
		}
	}
	cfg := Config{Ciphers: ciphers, MACs: macs}
	cfg.SetDefaults()
	if len(cfg.Ciphers) != 0 || len(cfg.MACs) != 0 {
		t.Errorf("explicit config kept %v %v", cfg.Ciphers, cfg.MACs)
	}

	// Default server and client: neither KEXINIT names a legacy algorithm.
	c1, c2, _ := netPipe()
	srv := &ServerConfig{PasswordCallback: func(ConnMetadata, []byte) (*Permissions, error) { return nil, errDeniedTest }}
	srv.AddHostKey(testSigners["rsa"])
	go NewServerConn(c1, srv)
	cc, err := NewUnauthClientConn(c2, "x", &ClientConfig{User: "u", HostKeyCallback: InsecureIgnoreHostKey()})
	if err == nil {
		k := cc.ServerKexInit
		for _, l := range [][]string{k.CiphersClientServer, k.MACsClientServer} {
			for _, n := range legacy {
				if slices.Contains(l, n) {
					t.Errorf("default server offers %s", n)
				}
			}
		}
	}
	c2.Close()

	// A personality client offering only legacy ciphers gets nothing from
	// a default server.
	c1, c2, _ = netPipe()
	go NewServerConn(c1, srv)
	_, _, _, err = NewClientConn(c2, "x", &ClientConfig{User: "u", HostKeyCallback: InsecureIgnoreHostKey(), Auth: []AuthMethod{Password("x")},
		Config: Config{Personality: &Personality{Ciphers: ciphers}}})
	var ne *AlgorithmNegotiationError
	if !errors.As(err, &ne) {
		t.Errorf("default server with legacy-only client: %v", err)
	}
	c2.Close()

	// A default client never offers them either.
	c1, c2, _ = netPipe()
	p := &Personality{KeyExchanges: []string{KeyExchangeCurve25519}, HostKeyAlgorithms: []string{KeyAlgoRSASHA256},
		Ciphers: ciphers, MACs: macs}
	psrv := &ServerConfig{Config: Config{Personality: p}, NoClientAuth: true}
	psrv.AddHostKey(testSigners["rsa"])
	go NewServerConn(c1, psrv)
	_, _, _, err = NewClientConn(c2, "x", &ClientConfig{User: "u", HostKeyCallback: InsecureIgnoreHostKey()})
	if !errors.As(err, &ne) {
		t.Errorf("default client with legacy-only server: %v", err)
	}
	c2.Close()
}

// legacyEcho runs a login and a session that echoes size bytes both ways,
// with a small rekey threshold so several key exchanges happen mid-stream.
func legacyEcho(t *testing.T, sp, cp *Personality, signer Signer, size int) error {
	t.Helper()
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	defer c2.Close()
	srv := &ServerConfig{Config: Config{Personality: sp, RekeyThreshold: 64 << 10},
		PasswordCallback: func(ConnMetadata, []byte) (*Permissions, error) { return nil, nil }}
	srv.AddHostKey(signer)
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
		buf := make([]byte, size)
		if _, err := io.ReadFull(ch, buf); err != nil {
			done <- err
			return
		}
		_, err = ch.Write(buf)
		ch.CloseWrite()
		done <- err
	}()
	cfg := &ClientConfig{User: "u", Auth: []AuthMethod{Password("x")}, HostKeyCallback: InsecureIgnoreHostKey(),
		Config: Config{Personality: cp, RekeyThreshold: 64 << 10}}
	conn, chans, reqs, err := NewClientConn(c2, "x", cfg)
	if err != nil {
		return err
	}
	client := NewClient(conn, chans, reqs)
	defer client.Close()
	ch, _, err := client.OpenChannel("session", nil)
	if err != nil {
		return err
	}
	msg := make([]byte, size)
	rand.Read(msg)
	go ch.Write(msg)
	got, err := io.ReadAll(ch)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, msg) {
		return errors.New("echo differs")
	}
	if err := <-done; err != nil {
		return err
	}
	if sid := conn.(*connection).transport.(*handshakeTransport).sessionID; sid == nil {
		return errors.New("no session")
	}
	return nil
}

// A dropbear 0.53-like server and an in-process client, forcing each legacy
// cipher, MAC, key exchange and host key in turn; each run echoes 300 KiB
// both ways across several rekeys.
func TestLegacyHandshakes(t *testing.T) {
	ciphers, macs := legacyNames()
	ciphers = append(ciphers, InsecureCipherAES128CBC, InsecureCipherTripleDESCBC, InsecureCipherRC4, InsecureCipherRC4128, InsecureCipherRC4256)
	gx, _ := WellKnownDHGroups(1024, 1536, 2048)
	server := &Personality{
		KeyExchanges:      []string{InsecureKeyExchangeDH1SHA1, InsecureKeyExchangeDH14SHA1, InsecureKeyExchangeDHGEXSHA1, KeyExchangeDHGEXSHA256},
		HostKeyAlgorithms: []string{KeyAlgoRSA, InsecureKeyAlgoDSA},
		Ciphers:           ciphers,
		MACs:              append(slices.Clone(macs), HMACSHA1, InsecureHMACSHA196),
		Compressions:      []string{compressionNone},
		ExtInfo:           []ExtInfoField{},
		GroupExchange:     &GroupExchange{MinBits: 1024, Groups: gx},
	}
	run := func(name string, cp *Personality, signer Signer) {
		t.Run(name, func(t *testing.T) {
			if err := legacyEcho(t, server, cp, signer, 300<<10); err != nil {
				t.Fatal(err)
			}
		})
	}
	base := func() *Personality {
		return &Personality{KeyExchanges: []string{InsecureKeyExchangeDH14SHA1}, HostKeyAlgorithms: []string{KeyAlgoRSA},
			Ciphers: []string{CipherAES256CBC}, MACs: []string{HMACMD5}, Compressions: []string{compressionNone}}
	}
	for _, c := range ciphers {
		p := base()
		p.Ciphers = []string{c}
		run("cipher/"+c, p, testSigners["rsa"])
	}
	for _, m := range server.MACs {
		for _, c := range []string{CipherBlowfishCBC, CipherTripleDESCTR} {
			p := base()
			p.Ciphers, p.MACs = []string{c}, []string{m}
			run("mac/"+m+"/"+c, p, testSigners["rsa"])
		}
	}
	for _, k := range server.KeyExchanges {
		p := base()
		p.KeyExchanges = []string{k}
		p.GroupExchange = &GroupExchange{Request: [3]uint32{1024, 1024, 8192}}
		run("kex/"+k, p, testSigners["rsa"])
	}
	p := base()
	p.HostKeyAlgorithms = []string{InsecureKeyAlgoDSA}
	run("hostkey/ssh-dss", p, testSigners["dsa"])
	run("hostkey/ssh-rsa", base(), testSigners["rsa"])
}

// Strict KEX engages only when both sides advertise it; a dropbear 0.53 or
// IOS personality, which does not, keeps counting sequence numbers across
// NEWKEYS, and both still work through rekeys.
func TestLegacyStrictKex(t *testing.T) {
	for _, strict := range []bool{false, true} {
		kex := []string{InsecureKeyExchangeDH14SHA1}
		if strict {
			kex = append(kex, kexStrictServer)
		}
		sp := &Personality{KeyExchanges: kex, HostKeyAlgorithms: []string{KeyAlgoRSA}, Ciphers: []string{InsecureCipherTripleDESCBC},
			MACs: []string{HMACMD5}, Compressions: []string{compressionNone}}
		cp := &Personality{KeyExchanges: []string{InsecureKeyExchangeDH14SHA1, kexStrictClient}, HostKeyAlgorithms: []string{KeyAlgoRSA},
			Ciphers: []string{InsecureCipherTripleDESCBC}, MACs: []string{HMACMD5}}
		c1, c2, _ := netPipe()
		srv := &ServerConfig{Config: Config{Personality: sp}, NoClientAuth: true}
		srv.AddHostKey(testSigners["rsa"])
		go NewServerConn(c1, srv)
		conn, _, _, err := NewClientConn(c2, "x", &ClientConfig{User: "u", HostKeyCallback: InsecureIgnoreHostKey(), Config: Config{Personality: cp}})
		if err != nil {
			t.Fatal(err)
		}
		ht := conn.(*connection).transport.(*handshakeTransport)
		if ht.strictMode != strict {
			t.Errorf("strict advertised %v, client strict mode %v", strict, ht.strictMode)
		}
		// Sequence numbers: without strict KEX they carry on from the
		// cleartext packets (KEXINIT, DH, NEWKEYS, then service request).
		if tr := ht.conn.(*transport); strict == (tr.writer.seqNum > 3) {
			t.Errorf("strict %v: write seq %d", strict, tr.writer.seqNum)
		}
		conn.Close()
	}
}

// OpenSSH's countermeasure for every CBC cipher: whichever check fails, the
// reader consumes exactly 256 KiB from the start of the packet before giving
// up. EtM and dropbear-style readers fail at once.
func TestLegacyCBCDiscard(t *testing.T) {
	kr := &kexResult{Hash: crypto.SHA1, K: []byte{1}, H: []byte{2}, SessionID: []byte{3}}
	for _, c := range []string{CipherBlowfishCBC, CipherAES256CBC, CipherTwofish128CBC, InsecureCipherTripleDESCBC} {
		for _, tc := range []struct {
			mac    string
			close  bool
			reads  int // -1: exactly maxPacket
			corrup []int
		}{
			{HMACMD5, false, -1, []int{0, 3, 9, 30}},
			{HMACMD5ETM, false, 0, []int{9, 30}},
			{HMACMD5, true, 0, []int{30}},
		} {
			algs := DirectionAlgorithms{Cipher: c, MAC: tc.mac, compression: compressionNone, legacy: true, closeOnCorrupt: tc.close}
			w, _ := newPacketCipher(clientKeys, algs, kr)
			pkt := &bytes.Buffer{}
			w.writeCipherPacket(0, pkt, rand.Reader, []byte("paperdrake legacy cbc"))
			n := pkt.Len()
			pkt.Write(make([]byte, 2*maxPacket))
			for _, i := range tc.corrup {
				r, _ := newPacketCipher(clientKeys, algs, kr)
				b := bytes.NewBuffer(slices.Clone(pkt.Bytes()))
				b.Bytes()[i] ^= 0x80
				before := b.Len()
				if _, err := r.readCipherPacket(0, b); err == nil {
					t.Fatalf("%s/%s byte %d: accepted", c, tc.mac, i)
				}
				read := before - b.Len()
				if tc.reads == -1 && read != maxPacket {
					t.Errorf("%s/%s byte %d: read %d, want %d", c, tc.mac, i, read, maxPacket)
				}
				if tc.reads == 0 && read > n {
					t.Errorf("%s/%s close=%v byte %d: read %d past the packet", c, tc.mac, tc.close, i, read)
				}
			}
		}
	}
}

// A packet whose MAC verifies but whose padding length is under 4 gets
// OpenSSH's "Corrupted padlen" disconnect.
func TestLegacyCorruptPadlen(t *testing.T) {
	kr := &kexResult{Hash: crypto.SHA1, K: []byte{1}, H: []byte{2}, SessionID: []byte{3}}
	algs := DirectionAlgorithms{Cipher: CipherBlowfishCBC, MAC: HMACMD5, compression: compressionNone, legacy: true}
	r, _ := newPacketCipher(clientKeys, algs, kr)
	w, _ := newPacketCipher(clientKeys, algs, kr)
	c := w.(*cbcCipher)
	// Hand-build a 16-byte packet with padding length 2 and a valid MAC.
	plain := []byte{0, 0, 0, 12, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0}
	c.mac.Reset()
	c.mac.Write([]byte{0, 0, 0, 0})
	c.mac.Write(plain)
	sum := c.mac.Sum(nil)
	c.encrypter.CryptBlocks(plain, plain)
	_, err := r.readCipherPacket(0, bytes.NewReader(append(plain, sum...)))
	var ce *corruptPacketError
	if !errors.As(err, &ce) || ce.msg != "Corrupted padlen 2 on input." {
		t.Fatalf("got %v", err)
	}
}

// The none cipher and MAC run only when both sides list them.
func TestLegacyNone(t *testing.T) {
	sp := &Personality{KeyExchanges: []string{InsecureKeyExchangeDH14SHA1}, HostKeyAlgorithms: []string{KeyAlgoRSA},
		Ciphers: []string{CipherAES128CTR, CipherNone}, MACs: []string{HMACSHA1, MACNone}, Compressions: []string{compressionNone}}
	cp := &Personality{KeyExchanges: []string{InsecureKeyExchangeDH14SHA1}, HostKeyAlgorithms: []string{KeyAlgoRSA},
		Ciphers: []string{CipherNone}, MACs: []string{MACNone}, Compressions: []string{compressionNone}}
	if err := legacyEcho(t, sp, cp, testSigners["rsa"], 100<<10); err != nil {
		t.Fatal(err)
	}
	cp.Ciphers = []string{CipherNone}
	sp.Ciphers = []string{CipherAES128CTR}
	if err := legacyEcho(t, sp, cp, testSigners["rsa"], 1); err == nil {
		t.Fatal("none negotiated against a server that does not list it")
	}
}

// Group exchange picks as OpenSSH's choose_dh does and falls back to group
// 14/16/18 when no modulus fits; the well-known groups are safe primes.
func TestGroupExchangeChoice(t *testing.T) {
	all, err := WellKnownDHGroups(1024, 1536, 2048, 3072, 4096, 6144, 8192)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range all {
		q := new(big.Int).Rsh(g.P, 1)
		if !g.P.ProbablyPrime(8) || !q.ProbablyPrime(8) {
			t.Fatalf("%d-bit group is not a safe prime", g.P.BitLen())
		}
	}
	gx := &GroupExchange{MinBits: 1024, Groups: all[:5]}
	for _, tc := range []struct {
		min, n, max uint32
		want        int
	}{
		{1024, 1024, 8192, 1024}, {1024, 2000, 8192, 2048}, {2048, 3072, 8192, 3072}, {1024, 8192, 8192, 4096},
		{512, 512, 1024, 1024}, {6144, 7680, 8192, 8192}, {1024, 7680, 8192, 4096},
	} {
		_, p, err := gx.choose(kexDHGexRequestMsg{MinBits: tc.min, PreferredBits: tc.n, MaxBits: tc.max})
		if err != nil || p.BitLen() != tc.want {
			t.Errorf("%d/%d/%d: got %v bits, err %v; want %d", tc.min, tc.n, tc.max, p.BitLen(), err, tc.want)
		}
	}
	if _, _, err := (&GroupExchange{}).choose(kexDHGexRequestMsg{MinBits: 1024, PreferredBits: 1024, MaxBits: 1024}); err == nil {
		t.Error("max below DH_GRP_MIN accepted")
	}
}

func TestDSAOpenSSHPrivateKey(t *testing.T) {
	var k dsa.PrivateKey
	if err := dsa.GenerateParameters(&k.Parameters, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	dsa.GenerateKey(&k, rand.Reader)
	block, err := MarshalPrivateKey(&k, "c")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParsePrivateKey(pem.EncodeToMemory(block))
	if err != nil {
		t.Fatal(err)
	}
	if s.PublicKey().Type() != InsecureKeyAlgoDSA || !bytes.Equal(s.PublicKey().Marshal(), (*dsaPublicKey)(&k.PublicKey).Marshal()) {
		t.Fatal("round trip changed the key")
	}
}
