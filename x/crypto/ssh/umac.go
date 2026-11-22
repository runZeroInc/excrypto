package ssh

import (
	"encoding/binary"
	"hash"
	"math/big"
	"math/bits"

	"github.com/runZeroInc/excrypto/crypto/aes"
	"github.com/runZeroInc/excrypto/crypto/cipher"
)

// UMAC (RFC 4418) with AES-128, as OpenSSH runs it: a 16-byte key, the
// 64-bit packet sequence number as the nonce, and the packet as the message.
const (
	UMAC64     = "umac-64@openssh.com"
	UMAC128    = "umac-128@openssh.com"
	UMAC64ETM  = "umac-64-etm@openssh.com"
	UMAC128ETM = "umac-128-etm@openssh.com"
)

func init() {
	macModes[UMAC64] = &macMode{16, false, func(key []byte) hash.Hash { return newUMAC(key, 8) }}
	macModes[UMAC128] = &macMode{16, false, func(key []byte) hash.Hash { return newUMAC(key, 16) }}
	macModes[UMAC64ETM] = &macMode{16, true, func(key []byte) hash.Hash { return newUMAC(key, 8) }}
	macModes[UMAC128ETM] = &macMode{16, true, func(key []byte) hash.Hash { return newUMAC(key, 16) }}
}

const (
	umacP36 = 1<<36 - 5
	umacP64 = 0xFFFFFFFFFFFFFFC5
)

var umacP128, umacOff128, umacMax128 = func() (*big.Int, *big.Int, *big.Int) {
	one := big.NewInt(1)
	p := new(big.Int).Sub(new(big.Int).Lsh(one, 128), big.NewInt(159))
	off := new(big.Int).Sub(new(big.Int).Lsh(one, 128), p)
	max := new(big.Int).Sub(new(big.Int).Lsh(one, 128), new(big.Int).Lsh(one, 96))
	return p, off, max
}()

// umacKey is the key schedule for one UMAC key and tag length.
type umacKey struct {
	taglen int
	l1     []uint32    // 256 + 4*(iters-1) words
	k64    []uint64    // per iteration
	k128   []*big.Int  // per iteration
	l3k1   [][8]uint64 // per iteration, reduced mod p36
	l3k2   []uint32    // per iteration
	pdf    cipher.Block
}

// umac is a hash.Hash whose first four bytes after Reset are the SSH
// sequence number (the nonce) and the rest the message.
type umac struct {
	k     *umacKey
	nonce [16]byte
	n     int // nonce bytes seen
	msg   []byte
}

func umacKDF(b cipher.Block, index uint64, n int) []byte {
	out := make([]byte, 0, n+16)
	var t [16]byte
	for i := uint64(1); len(out) < n; i++ {
		binary.BigEndian.PutUint64(t[0:8], index)
		binary.BigEndian.PutUint64(t[8:16], i)
		var o [16]byte
		b.Encrypt(o[:], t[:])
		out = append(out, o[:]...)
	}
	return out[:n]
}

func newUMACKey(key []byte, taglen int) *umacKey {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	iters := taglen / 4
	k := &umacKey{taglen: taglen}
	l1 := umacKDF(b, 1, 1024+(iters-1)*16)
	k.l1 = make([]uint32, len(l1)/4)
	for i := range k.l1 {
		k.l1[i] = binary.BigEndian.Uint32(l1[4*i:])
	}
	l2 := umacKDF(b, 2, iters*24)
	l31 := umacKDF(b, 3, iters*64)
	l32 := umacKDF(b, 4, iters*4)
	for i := 0; i < iters; i++ {
		kk := l2[i*24:]
		k.k64 = append(k.k64, binary.BigEndian.Uint64(kk)&0x01ffffff01ffffff)
		k128 := make([]byte, 16)
		for j := range k128 {
			k128[j] = kk[8+j] & [4]byte{0x01, 0xff, 0xff, 0xff}[j%4]
		}
		k.k128 = append(k.k128, new(big.Int).SetBytes(k128))
		var k1 [8]uint64
		for j := range k1 {
			k1[j] = binary.BigEndian.Uint64(l31[i*64+j*8:]) % umacP36
		}
		k.l3k1 = append(k.l3k1, k1)
		k.l3k2 = append(k.l3k2, binary.BigEndian.Uint32(l32[i*4:]))
	}
	pk := umacKDF(b, 0, 16)
	if k.pdf, err = aes.NewCipher(pk); err != nil {
		panic(err)
	}
	return k
}

func newUMAC(key []byte, taglen int) *umac {
	return &umac{k: newUMACKey(key, taglen)}
}

func (u *umac) Size() int      { return u.k.taglen }
func (u *umac) BlockSize() int { return 32 }

func (u *umac) Reset() {
	u.n = 0
	u.nonce = [16]byte{}
	u.msg = u.msg[:0]
}

func (u *umac) Write(p []byte) (int, error) {
	n := len(p)
	for u.n < 4 && len(p) > 0 {
		u.nonce[4+u.n] = p[0]
		u.n++
		p = p[1:]
	}
	u.msg = append(u.msg, p...)
	return n, nil
}

func (u *umac) Sum(in []byte) []byte {
	return append(in, umacTag(u.k, u.msg, u.nonce[:8])...)
}

// umacTag is RFC 4418 UMAC with an 8-byte nonce.
func umacTag(k *umacKey, msg, nonce []byte) []byte {
	tag := uhash(k, msg)
	var n [16]byte
	copy(n[:], nonce)
	index := 0
	if k.taglen <= 8 {
		mask := byte(16/k.taglen - 1)
		index = int(n[len(nonce)-1] & mask)
		n[len(nonce)-1] &^= mask
	}
	var t [16]byte
	k.pdf.Encrypt(t[:], n[:])
	pad := t[index*k.taglen : index*k.taglen+k.taglen]
	for i := range tag {
		tag[i] ^= pad[i]
	}
	return tag
}

func uhash(k *umacKey, m []byte) []byte {
	iters := k.taglen / 4
	out := make([]byte, 0, k.taglen)
	for i := 0; i < iters; i++ {
		a := l1Hash(k.l1[i*4:i*4+256], m)
		var b [16]byte
		if len(m) <= 1024 {
			copy(b[8:], a)
		} else {
			l2Hash(k.k64[i], k.k128[i], a).FillBytes(b[:])
		}
		out = binary.BigEndian.AppendUint32(out, l3Hash(&k.l3k1[i], k.l3k2[i], b[:]))
	}
	return out
}

func l1Hash(key []uint32, m []byte) []byte {
	var y []byte
	var chunk [1024]byte
	for {
		n := min(len(m), 1024)
		last := len(m) <= 1024
		bitlen := uint64(n) * 8
		c := chunk[:copy(chunk[:], m[:n])]
		if last {
			pad := (32 - len(c)%32) % 32
			if len(c) == 0 {
				pad = 32
			}
			for i := 0; i < pad; i++ {
				c = append(c, 0)
			}
		}
		y = binary.BigEndian.AppendUint64(y, nh(key, c)+bitlen)
		if last {
			return y
		}
		m = m[1024:]
	}
}

// nh reads the message little-endian (RFC 4418 ENDIAN-SWAP).
func nh(key []uint32, m []byte) uint64 {
	var y uint64
	t := len(m) / 4
	for i := 0; i < t; i += 8 {
		for j := 0; j < 4; j++ {
			a := binary.LittleEndian.Uint32(m[4*(i+j):]) + key[i+j]
			b := binary.LittleEndian.Uint32(m[4*(i+j+4):]) + key[i+j+4]
			y += uint64(a) * uint64(b)
		}
	}
	return y
}

func poly64(k, y, m uint64) uint64 {
	hi, lo := bits.Mul64(k, y)
	var c uint64
	lo, c = bits.Add64(lo, m, 0)
	hi += c
	_, r := bits.Div64(hi, lo, umacP64)
	return r
}

func l2Hash(k64 uint64, k128 *big.Int, m []byte) *big.Int {
	const offset64 = 1<<64 - umacP64
	const max64 = 1<<64 - 1<<32
	m1 := m
	if len(m1) > 1<<17 {
		m1 = m[:1<<17]
	}
	y := uint64(1)
	for i := 0; i+8 <= len(m1); i += 8 {
		w := binary.BigEndian.Uint64(m1[i:])
		if w >= max64 {
			y = poly64(k64, y, umacP64-1)
			y = poly64(k64, y, w-offset64)
		} else {
			y = poly64(k64, y, w)
		}
	}
	if len(m) <= 1<<17 {
		return new(big.Int).SetUint64(y)
	}
	m2 := append([]byte{}, m[1<<17:]...)
	m2 = append(m2, 0x80)
	for len(m2)%16 != 0 {
		m2 = append(m2, 0)
	}
	in := make([]byte, 16, 16+len(m2))
	binary.BigEndian.PutUint64(in[8:], y)
	in = append(in, m2...)
	marker := new(big.Int).Sub(umacP128, big.NewInt(1))
	yy := big.NewInt(1)
	w := new(big.Int)
	step := func(v *big.Int) {
		yy.Mul(yy, k128)
		yy.Add(yy, v)
		yy.Mod(yy, umacP128)
	}
	for i := 0; i < len(in); i += 16 {
		w.SetBytes(in[i : i+16])
		if w.Cmp(umacMax128) >= 0 {
			step(marker)
			step(new(big.Int).Sub(w, umacOff128))
		} else {
			step(w)
		}
	}
	return yy
}

func l3Hash(k1 *[8]uint64, k2 uint32, m []byte) uint32 {
	var y uint64
	for i := 0; i < 8; i++ {
		y += uint64(binary.BigEndian.Uint16(m[2*i:])) * k1[i]
	}
	return uint32(y%umacP36) ^ k2
}
