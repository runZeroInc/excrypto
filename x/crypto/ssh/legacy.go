package ssh

import (
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/runZeroInc/excrypto/crypto/aes"
	"github.com/runZeroInc/excrypto/crypto/cipher"
	"github.com/runZeroInc/excrypto/crypto/des"
	"github.com/runZeroInc/excrypto/crypto/hmac"
	"github.com/runZeroInc/excrypto/crypto/md5"
	"github.com/runZeroInc/excrypto/crypto/sha1"
	"github.com/runZeroInc/excrypto/crypto/sha256"
	"github.com/runZeroInc/excrypto/crypto/sha512"
	"github.com/runZeroInc/excrypto/x/crypto/blowfish"
	"github.com/runZeroInc/excrypto/x/crypto/cast5"
	"github.com/runZeroInc/excrypto/x/crypto/ripemd160"
	"github.com/runZeroInc/excrypto/x/crypto/twofish"
)

// Legacy algorithms. They are weak, and run only on a connection whose Config
// carries a Personality: a server that advertises them, or a client told to
// offer them. No default list, SupportedAlgorithms or InsecureAlgorithms
// names them; PersonalityAlgorithms does.
const (
	CipherNone          = "none"
	CipherAES192CBC     = "aes192-cbc"
	CipherAES256CBC     = "aes256-cbc"
	CipherRijndaelCBC   = "rijndael-cbc@lysator.liu.se"
	CipherBlowfishCBC   = "blowfish-cbc"
	CipherCAST128CBC    = "cast128-cbc"
	CipherTwofishCBC    = "twofish-cbc"
	CipherTwofish128CBC = "twofish128-cbc"
	CipherTwofish192CBC = "twofish192-cbc"
	CipherTwofish256CBC = "twofish256-cbc"
	CipherTripleDESCTR  = "3des-ctr"
	CipherBlowfishCTR   = "blowfish-ctr"
	CipherCAST128CTR    = "cast128-ctr"
	CipherTwofish128CTR = "twofish128-ctr"
	CipherTwofish192CTR = "twofish192-ctr"
	CipherTwofish256CTR = "twofish256-ctr"

	MACNone              = "none"
	HMACMD5              = "hmac-md5"
	HMACMD596            = "hmac-md5-96"
	HMACSHA256_96        = "hmac-sha2-256-96"
	HMACSHA512_96        = "hmac-sha2-512-96"
	HMACRIPEMD160        = "hmac-ripemd160"
	HMACRIPEMD160OpenSSH = "hmac-ripemd160@openssh.com"
	HMACMD5ETM           = "hmac-md5-etm@openssh.com"
	HMACMD596ETM         = "hmac-md5-96-etm@openssh.com"
	HMACSHA196ETM        = "hmac-sha1-96-etm@openssh.com"
	HMACRIPEMD160ETM     = "hmac-ripemd160-etm@openssh.com"
)

var (
	legacyCipherModes = map[string]*cipherMode{}
	legacyMACModes    = map[string]*macMode{}
	// legacyWideBlock are the legacy ciphers with a 16-byte block.
	legacyWideBlock = map[string]bool{}
)

func init() {
	aesNew := func(k []byte) (cipher.Block, error) { return aes.NewCipher(k) }
	bfNew := func(k []byte) (cipher.Block, error) { return blowfish.NewCipher(k) }
	castNew := func(k []byte) (cipher.Block, error) { return cast5.NewCipher(k) }
	tfNew := func(k []byte) (cipher.Block, error) { return twofish.NewCipher(k) }
	desNew := func(k []byte) (cipher.Block, error) { return des.NewTripleDESCipher(k) }

	cbc := func(name string, key, block int, nb func([]byte) (cipher.Block, error)) {
		legacyCipherModes[name] = &cipherMode{key, block, cbcMode(nb)}
		legacyWideBlock[name] = block == 16
	}
	ctr := func(name string, key, block int, nb func([]byte) (cipher.Block, error)) {
		legacyCipherModes[name] = &cipherMode{key, block, streamCipherModeBlock(0, block, ctrStream(nb))}
		legacyWideBlock[name] = block == 16
	}
	// Key sizes as OpenSSH's cipher.c, dropbear and RFC 4253/4344 give them.
	cbc(CipherAES192CBC, 24, 16, aesNew)
	cbc(CipherAES256CBC, 32, 16, aesNew)
	cbc(CipherRijndaelCBC, 32, 16, aesNew)
	cbc(CipherBlowfishCBC, 16, 8, bfNew)
	cbc(CipherCAST128CBC, 16, 8, castNew)
	cbc(CipherTwofishCBC, 32, 16, tfNew)
	cbc(CipherTwofish128CBC, 16, 16, tfNew)
	cbc(CipherTwofish192CBC, 24, 16, tfNew)
	cbc(CipherTwofish256CBC, 32, 16, tfNew)
	ctr(CipherTripleDESCTR, 24, 8, desNew)
	ctr(CipherBlowfishCTR, 32, 8, bfNew)
	ctr(CipherCAST128CTR, 16, 8, castNew)
	ctr(CipherTwofish128CTR, 16, 16, tfNew)
	ctr(CipherTwofish192CTR, 24, 16, tfNew)
	ctr(CipherTwofish256CTR, 32, 16, tfNew)
	// OpenSSH's "none" cipher has an 8-byte block.
	legacyCipherModes[CipherNone] = &cipherMode{0, 0, streamCipherModeBlock(0, 8, func(_, _ []byte) (cipher.Stream, error) {
		return noneCipher{}, nil
	})}

	hm := func(name string, key, trunc int, etm bool, h func() hash.Hash) {
		legacyMACModes[name] = &macMode{key, etm, func(k []byte) hash.Hash {
			m := hmac.New(h, k)
			if trunc > 0 {
				return truncatingMAC{trunc, m}
			}
			return m
		}}
	}
	hm(HMACMD5, 16, 0, false, md5.New)
	hm(HMACMD596, 16, 12, false, md5.New)
	hm(HMACSHA256_96, 32, 12, false, sha256.New)
	hm(HMACSHA512_96, 64, 12, false, sha512.New)
	hm(HMACRIPEMD160, 20, 0, false, ripemd160.New)
	hm(HMACRIPEMD160OpenSSH, 20, 0, false, ripemd160.New)
	hm(HMACMD5ETM, 16, 0, true, md5.New)
	hm(HMACMD596ETM, 16, 12, true, md5.New)
	hm(HMACSHA196ETM, 20, 12, true, sha1.New)
	hm(HMACRIPEMD160ETM, 20, 0, true, ripemd160.New)
	legacyMACModes[MACNone] = &macMode{0, false, func([]byte) hash.Hash { return nil }}
}

// cipherModeFor looks a cipher up, reaching the legacy set only when allowed.
func cipherModeFor(name string, legacy bool) *cipherMode {
	if m := cipherModes[name]; m != nil {
		return m
	}
	if legacy {
		return legacyCipherModes[name]
	}
	return nil
}

// macModeFor looks a MAC up, reaching the legacy set only when allowed.
func macModeFor(name string, legacy bool) *macMode {
	if m := macModes[name]; m != nil {
		return m
	}
	if legacy {
		return legacyMACModes[name]
	}
	return nil
}

func cbcMode(newBlock func([]byte) (cipher.Block, error)) func(key, iv, macKey []byte, algs DirectionAlgorithms) (packetCipher, error) {
	return func(key, iv, macKey []byte, algs DirectionAlgorithms) (packetCipher, error) {
		c, err := newBlock(key)
		if err != nil {
			return nil, err
		}
		return newCBCCipher(c, key, iv, macKey, algs)
	}
}

// ctrStream is RFC 4344 counter mode: the IV is a big-endian counter as wide
// as the block.
func ctrStream(newBlock func([]byte) (cipher.Block, error)) func(key, iv []byte) (cipher.Stream, error) {
	return func(key, iv []byte) (cipher.Stream, error) {
		c, err := newBlock(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewCTR(c, iv), nil
	}
}

// legacyNames returns the legacy cipher and MAC names in a stable order.
func legacyNames() (ciphers, macs []string) {
	ciphers = []string{CipherAES192CBC, CipherAES256CBC, CipherRijndaelCBC, CipherBlowfishCBC, CipherCAST128CBC,
		CipherTwofishCBC, CipherTwofish128CBC, CipherTwofish192CBC, CipherTwofish256CBC, CipherTripleDESCTR,
		CipherBlowfishCTR, CipherCAST128CTR, CipherTwofish128CTR, CipherTwofish192CTR, CipherTwofish256CTR, CipherNone}
	macs = []string{HMACMD5, HMACMD596, HMACSHA256_96, HMACSHA512_96, HMACRIPEMD160, HMACRIPEMD160OpenSSH,
		HMACMD5ETM, HMACMD596ETM, HMACSHA196ETM, HMACRIPEMD160ETM, MACNone}
	return
}

// DHGroup is one diffie-hellman-group-exchange modulus.
type DHGroup struct {
	G, P *big.Int
}

// GroupExchange is what a diffie-hellman-group-exchange server accepts and
// offers, as OpenSSH's DH_GRP_MIN, DH_GRP_MAX and moduli file set it.
type GroupExchange struct {
	// MinBits is the floor applied to a request (DH_GRP_MIN). Zero means 2048.
	MinBits uint32
	// MaxBits is the ceiling applied to a request (DH_GRP_MAX). Zero means 8192.
	MaxBits uint32
	// Groups are the moduli the server picks from. When none fits, the
	// server answers with OpenSSH's fallback: group 14, 16 or 18 by the
	// request's maximum.
	Groups []DHGroup
	// Request, on a client, is the min, preferred and max sent. Zero sends
	// this package's 2048, 2048, 8192.
	Request [3]uint32
}

var wellKnownDH = map[int]string{
	1024: oakleyGroup2, 1536: oakleyGroup5, 2048: oakleyGroup14, 3072: oakleyGroup15,
	4096: oakleyGroup16, 6144: oakleyGroup17, 8192: oakleyGroup18,
}

// WellKnownDHGroups returns the RFC 2409 / RFC 3526 MODP groups of the given
// sizes (1024, 1536, 2048, 3072, 4096, 6144 or 8192 bits), generator 2.
func WellKnownDHGroups(bits ...int) ([]DHGroup, error) {
	var out []DHGroup
	for _, b := range bits {
		h, ok := wellKnownDH[b]
		if !ok {
			return nil, fmt.Errorf("ssh: no well-known %d-bit DH group", b)
		}
		p, _ := new(big.Int).SetString(h, 16)
		out = append(out, DHGroup{G: big.NewInt(2), P: p})
	}
	return out, nil
}

// choose picks a modulus as OpenSSH's choose_dh does, after kexgexs.c has
// clamped the request: among moduli within [min, max], the smallest above
// want, else the largest; a random one of that size.
func (g *GroupExchange) choose(req kexDHGexRequestMsg) (*big.Int, *big.Int, error) {
	lo, hi := g.limits()
	minB, maxB, want := max(lo, req.MinBits), min(hi, req.MaxBits), min(hi, max(lo, req.PreferredBits))
	if req.MaxBits < req.MinBits || req.PreferredBits < req.MinBits || req.MaxBits < req.PreferredBits || req.MaxBits < lo {
		return nil, nil, fmt.Errorf("ssh: DH GEX request out of range, min: %d, max: %d, preferred: %d",
			req.MinBits, req.MaxBits, req.PreferredBits)
	}
	best, count := 0, 0
	for _, grp := range g.Groups {
		size := grp.P.BitLen()
		if size > int(maxB) || size < int(minB) {
			continue
		}
		if (size > int(want) && size < best) || (size > best && best < int(want)) {
			best, count = size, 0
		}
		if size == best {
			count++
		}
	}
	if count == 0 {
		fb := 2048
		if maxB >= 6144 {
			fb = 8192
		} else if maxB >= 3072 {
			fb = 4096
		}
		grp, _ := WellKnownDHGroups(fb)
		return grp[0].G, grp[0].P, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(count)))
	if err != nil {
		return nil, nil, err
	}
	which := int(n.Int64())
	for _, grp := range g.Groups {
		if grp.P.BitLen() != best {
			continue
		}
		if which == 0 {
			return grp.G, grp.P, nil
		}
		which--
	}
	return nil, nil, errors.New("ssh: DH group selection failed")
}

func (g *GroupExchange) limits() (uint32, uint32) {
	lo, hi := g.MinBits, g.MaxBits
	if lo == 0 {
		lo = 2048
	}
	if hi == 0 {
		hi = 8192
	}
	return lo, hi
}

const oakleyGroup5 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"

const oakleyGroup17 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF"
