// Streamlined NTRU Prime sntrup761, ported from the public-domain SUPERCOP
// reference implementation (crypto_kem/sntrup761/ref) as carried in
// OpenSSH's sntrup761.c. Authors of the original: Daniel J. Bernstein,
// Chitchanok Chuengsatiansup, Tanja Lange, Christine van Vredendaal.
//
// This port is not constant-time: it exists so a server can complete the
// sntrup761x25519-sha512 key exchange that OpenSSH clients prefer.

package ssh

import (
	"io"
	"slices"

	"github.com/runZeroInc/excrypto/crypto/sha512"
)

const (
	sntrupP           = 761
	sntrupQ           = 4591
	sntrupW           = 286
	sntrupQ12         = (sntrupQ - 1) / 2
	sntrupRoundedSize = 1007
	sntrupRqSize      = 1158
	sntrupSmallSize   = (sntrupP + 3) / 4
	sntrupHashSize    = 32

	sntrupPublicKeySize  = sntrupRqSize
	sntrupCiphertextSize = sntrupRoundedSize + sntrupHashSize
	sntrupSecretKeySize  = 2*sntrupSmallSize + sntrupPublicKeySize + sntrupSmallSize + sntrupHashSize
	sntrupSharedKeySize  = 32
)

type sntrupSmall = int8
type sntrupFq = int16

// mod returns x mod m in [0, m).
func sntrupMod(x int32, m int32) int32 {
	r := x % m
	if r < 0 {
		r += m
	}
	return r
}

func f3Freeze(x int32) sntrupSmall { return sntrupSmall(sntrupMod(x+1, 3) - 1) }

func fqFreeze(x int32) sntrupFq { return sntrupFq(sntrupMod(x+sntrupQ12, sntrupQ) - sntrupQ12) }

func fqRecip(a1 sntrupFq) sntrupFq {
	ai := a1
	for i := 1; i < sntrupQ-2; i++ {
		ai = fqFreeze(int32(a1) * int32(ai))
	}
	return ai
}

// reduce folds a product of length 2p-1 modulo x^p - x - 1.
func sntrupReduce(fg []int32, freeze func(int32) int32) {
	for i := 2*sntrupP - 2; i >= sntrupP; i-- {
		fg[i-sntrupP] = freeze(fg[i-sntrupP] + fg[i])
		fg[i-sntrupP+1] = freeze(fg[i-sntrupP+1] + fg[i])
	}
}

func rqMultSmall(h []sntrupFq, f []sntrupFq, g []sntrupSmall) {
	var fg [2*sntrupP - 1]int32
	for i := 0; i < sntrupP; i++ {
		if g[i] == 0 {
			continue
		}
		gi := int32(g[i])
		for j := 0; j < sntrupP; j++ {
			fg[i+j] += int32(f[j]) * gi
		}
	}
	fz := func(x int32) int32 { return int32(fqFreeze(x)) }
	for i := range fg {
		fg[i] = fz(fg[i])
	}
	sntrupReduce(fg[:], fz)
	for i := 0; i < sntrupP; i++ {
		h[i] = sntrupFq(fg[i])
	}
}

func r3Mult(h []sntrupSmall, f []sntrupSmall, g []sntrupSmall) {
	var fg [2*sntrupP - 1]int32
	for i := 0; i < sntrupP; i++ {
		for j := 0; j < sntrupP; j++ {
			fg[i+j] += int32(f[i]) * int32(g[j])
		}
	}
	fz := func(x int32) int32 { return int32(f3Freeze(x)) }
	for i := range fg {
		fg[i] = fz(fg[i])
	}
	sntrupReduce(fg[:], fz)
	for i := 0; i < sntrupP; i++ {
		h[i] = sntrupSmall(fg[i])
	}
}

// r3Recip sets out = 1/in in R3 and reports success.
func r3Recip(out []sntrupSmall, in []sntrupSmall) bool {
	var f, g, v, r [sntrupP + 1]int32
	r[0] = 1
	f[0] = 1
	f[sntrupP-1], f[sntrupP] = -1, -1
	for i := 0; i < sntrupP; i++ {
		g[sntrupP-1-i] = int32(in[i])
	}
	delta := 1
	for loop := 0; loop < 2*sntrupP-1; loop++ {
		copy(v[1:], v[:sntrupP])
		v[0] = 0
		sign := -g[0] * f[0]
		if delta > 0 && g[0] != 0 {
			delta = -delta
			f, g = g, f
			v, r = r, v
		}
		delta++
		for i := range g {
			g[i] = int32(f3Freeze(g[i] + sign*f[i]))
		}
		for i := range r {
			r[i] = int32(f3Freeze(r[i] + sign*v[i]))
		}
		copy(g[:sntrupP], g[1:])
		g[sntrupP] = 0
	}
	sign := f[0]
	for i := 0; i < sntrupP; i++ {
		out[i] = sntrupSmall(sign * v[sntrupP-1-i])
	}
	return delta == 0
}

// rqRecip3 sets out = 1/(3*in) in Rq.
func rqRecip3(out []sntrupFq, in []sntrupSmall) bool {
	var f, g, v, r [sntrupP + 1]int32
	r[0] = int32(fqRecip(3))
	f[0] = 1
	f[sntrupP-1], f[sntrupP] = -1, -1
	for i := 0; i < sntrupP; i++ {
		g[sntrupP-1-i] = int32(in[i])
	}
	delta := 1
	for loop := 0; loop < 2*sntrupP-1; loop++ {
		copy(v[1:], v[:sntrupP])
		v[0] = 0
		if delta > 0 && g[0] != 0 {
			delta = -delta
			f, g = g, f
			v, r = r, v
		}
		delta++
		f0, g0 := f[0], g[0]
		for i := range g {
			g[i] = int32(fqFreeze(f0*g[i] - g0*f[i]))
		}
		for i := range r {
			r[i] = int32(fqFreeze(f0*r[i] - g0*v[i]))
		}
		copy(g[:sntrupP], g[1:])
		g[sntrupP] = 0
	}
	scale := int32(fqRecip(sntrupFq(f[0])))
	for i := 0; i < sntrupP; i++ {
		out[i] = fqFreeze(scale * v[sntrupP-1-i])
	}
	return delta == 0
}

func sntrupRandom32(rand io.Reader) (uint32, error) {
	var c [4]byte
	if _, err := io.ReadFull(rand, c[:]); err != nil {
		return 0, err
	}
	return uint32(c[0]) | uint32(c[1])<<8 | uint32(c[2])<<16 | uint32(c[3])<<24, nil
}

func shortRandom(rand io.Reader, out []sntrupSmall) error {
	var l [sntrupP]uint32
	for i := range l {
		x, err := sntrupRandom32(rand)
		if err != nil {
			return err
		}
		if i < sntrupW {
			l[i] = x &^ 1
		} else {
			l[i] = (x &^ 3) | 1
		}
	}
	slices.Sort(l[:])
	for i := range l {
		out[i] = sntrupSmall(l[i]&3) - 1
	}
	return nil
}

func smallRandom(rand io.Reader, out []sntrupSmall) error {
	for i := 0; i < sntrupP; i++ {
		x, err := sntrupRandom32(rand)
		if err != nil {
			return err
		}
		out[i] = sntrupSmall(((x&0x3fffffff)*3)>>30) - 1
	}
	return nil
}

func sntrupEncode(out []byte, r []uint16, m []uint16) []byte {
	n := len(r)
	if n == 1 {
		rr, mm := uint32(r[0]), uint32(m[0])
		for mm > 1 {
			out = append(out, byte(rr))
			rr >>= 8
			mm = (mm + 255) >> 8
		}
		return out
	}
	half := (n + 1) / 2
	r2 := make([]uint16, half)
	m2 := make([]uint16, half)
	i := 0
	for ; i < n-1; i += 2 {
		m0 := uint32(m[i])
		rr := uint32(r[i]) + uint32(r[i+1])*m0
		mm := uint32(m[i+1]) * m0
		for mm >= 16384 {
			out = append(out, byte(rr))
			rr >>= 8
			mm = (mm + 255) >> 8
		}
		r2[i/2] = uint16(rr)
		m2[i/2] = uint16(mm)
	}
	if i < n {
		r2[i/2] = r[i]
		m2[i/2] = m[i]
	}
	return sntrupEncode(out, r2, m2)
}

func sntrupDecode(out []uint16, s []byte, m []uint16) {
	n := len(m)
	if n == 1 {
		switch {
		case m[0] == 1:
			out[0] = 0
		case m[0] <= 256:
			out[0] = uint16(uint32(s[0]) % uint32(m[0]))
		default:
			out[0] = uint16((uint32(s[0]) + uint32(s[1])<<8) % uint32(m[0]))
		}
		return
	}
	half := (n + 1) / 2
	r2 := make([]uint16, half)
	m2 := make([]uint16, half)
	bottomr := make([]uint32, n/2)
	bottomt := make([]uint32, n/2)
	i := 0
	for ; i < n-1; i += 2 {
		mm := uint32(m[i]) * uint32(m[i+1])
		switch {
		case mm > 256*16383:
			bottomt[i/2] = 256 * 256
			bottomr[i/2] = uint32(s[0]) + 256*uint32(s[1])
			s = s[2:]
			m2[i/2] = uint16((((mm + 255) >> 8) + 255) >> 8)
		case mm >= 16384:
			bottomt[i/2] = 256
			bottomr[i/2] = uint32(s[0])
			s = s[1:]
			m2[i/2] = uint16((mm + 255) >> 8)
		default:
			bottomt[i/2] = 1
			m2[i/2] = uint16(mm)
		}
	}
	if i < n {
		m2[i/2] = m[i]
	}
	sntrupDecode(r2, s, m2)
	o := 0
	for i = 0; i < n-1; i += 2 {
		r := bottomr[i/2] + bottomt[i/2]*uint32(r2[i/2])
		out[o] = uint16(r % uint32(m[i]))
		out[o+1] = uint16((r / uint32(m[i])) % uint32(m[i+1]))
		o += 2
	}
	if i < n {
		out[o] = r2[i/2]
	}
}

func smallEncode(f []sntrupSmall) []byte {
	s := make([]byte, 0, sntrupSmallSize)
	i := 0
	for ; i < sntrupP/4; i++ {
		x := byte(f[4*i]+1) | byte(f[4*i+1]+1)<<2 | byte(f[4*i+2]+1)<<4 | byte(f[4*i+3]+1)<<6
		s = append(s, x)
	}
	return append(s, byte(f[4*i]+1))
}

func smallDecode(f []sntrupSmall, s []byte) {
	for i := 0; i < sntrupP/4; i++ {
		x := s[i]
		for k := 0; k < 4; k++ {
			f[4*i+k] = sntrupSmall(x&3) - 1
			x >>= 2
		}
	}
	f[sntrupP-1] = sntrupSmall(s[sntrupP/4]&3) - 1
}

func rqEncode(r []sntrupFq) []byte {
	var R, M [sntrupP]uint16
	for i := range R {
		R[i] = uint16(int32(r[i]) + sntrupQ12)
		M[i] = sntrupQ
	}
	return sntrupEncode(make([]byte, 0, sntrupRqSize), R[:], M[:])
}

func rqDecode(r []sntrupFq, s []byte) {
	var R, M [sntrupP]uint16
	for i := range M {
		M[i] = sntrupQ
	}
	sntrupDecode(R[:], s, M[:])
	for i := range R {
		r[i] = sntrupFq(int32(R[i]) - sntrupQ12)
	}
}

func roundedEncode(r []sntrupFq) []byte {
	var R, M [sntrupP]uint16
	for i := range R {
		R[i] = uint16(((int32(r[i]) + sntrupQ12) * 10923) >> 15)
		M[i] = (sntrupQ + 2) / 3
	}
	return sntrupEncode(make([]byte, 0, sntrupRoundedSize), R[:], M[:])
}

func roundedDecode(r []sntrupFq, s []byte) {
	var R, M [sntrupP]uint16
	for i := range M {
		M[i] = (sntrupQ + 2) / 3
	}
	sntrupDecode(R[:], s, M[:])
	for i := range R {
		r[i] = sntrupFq(int32(R[i])*3 - sntrupQ12)
	}
}

func sntrupHashPrefix(b byte, in ...[]byte) []byte {
	h := sha512.New()
	h.Write([]byte{b})
	for _, x := range in {
		h.Write(x)
	}
	return h.Sum(nil)[:sntrupHashSize]
}

// sntrupHide returns the ciphertext with its confirmation hash, and the encoded input.
func sntrupHide(r []sntrupSmall, pk []byte, cache []byte) (c []byte, rEnc []byte) {
	rEnc = smallEncode(r)
	var h, hr, ct [sntrupP]sntrupFq
	rqDecode(h[:], pk)
	rqMultSmall(hr[:], h[:], r)
	for i := range ct {
		ct[i] = hr[i] - sntrupFq(f3Freeze(int32(hr[i])))
	}
	c = roundedEncode(ct[:])
	c = append(c, sntrupHashPrefix(2, sntrupHashPrefix(3, rEnc), cache)...)
	return c, rEnc
}

// sntrupKeyPair returns a public and secret key.
func sntrupKeyPair(rand io.Reader) (pk, sk []byte, err error) {
	var g, ginv, f [sntrupP]sntrupSmall
	for {
		if err := smallRandom(rand, g[:]); err != nil {
			return nil, nil, err
		}
		if r3Recip(ginv[:], g[:]) {
			break
		}
	}
	if err := shortRandom(rand, f[:]); err != nil {
		return nil, nil, err
	}
	var finv, h [sntrupP]sntrupFq
	rqRecip3(finv[:], f[:])
	rqMultSmall(h[:], finv[:], g[:])
	pk = rqEncode(h[:])
	sk = append(smallEncode(f[:]), smallEncode(ginv[:])...)
	sk = append(sk, pk...)
	rho := make([]byte, sntrupSmallSize)
	if _, err := io.ReadFull(rand, rho); err != nil {
		return nil, nil, err
	}
	sk = append(sk, rho...)
	sk = append(sk, sntrupHashPrefix(4, pk)...)
	return pk, sk, nil
}

// sntrupEncap returns a ciphertext and shared key for pk.
func sntrupEncap(rand io.Reader, pk []byte) (c, k []byte, err error) {
	var r [sntrupP]sntrupSmall
	if err := shortRandom(rand, r[:]); err != nil {
		return nil, nil, err
	}
	c, rEnc := sntrupHide(r[:], pk, sntrupHashPrefix(4, pk))
	return c, sntrupHashPrefix(1, sntrupHashPrefix(3, rEnc), c), nil
}

// sntrupDecap returns the shared key for ciphertext c under sk.
func sntrupDecap(c, sk []byte) []byte {
	var f, v, r, ev, e [sntrupP]sntrupSmall
	smallDecode(f[:], sk)
	smallDecode(v[:], sk[sntrupSmallSize:])
	pk := sk[2*sntrupSmallSize : 2*sntrupSmallSize+sntrupPublicKeySize]
	rho := sk[2*sntrupSmallSize+sntrupPublicKeySize : 3*sntrupSmallSize+sntrupPublicKeySize]
	cache := sk[3*sntrupSmallSize+sntrupPublicKeySize:]

	var ct, cf [sntrupP]sntrupFq
	roundedDecode(ct[:], c)
	rqMultSmall(cf[:], ct[:], f[:])
	for i := range e {
		e[i] = f3Freeze(int32(fqFreeze(3 * int32(cf[i]))))
	}
	r3Mult(ev[:], e[:], v[:])
	weight := 0
	for i := range ev {
		weight += int(ev[i] & 1)
	}
	ok := weight == sntrupW
	for i := range r {
		switch {
		case !ok && i < sntrupW:
			r[i] = 1
		case !ok:
			r[i] = 0
		default:
			r[i] = ev[i]
		}
	}
	cnew, rEnc := sntrupHide(r[:], pk, cache)
	if string(cnew) != string(c[:sntrupCiphertextSize]) {
		return sntrupHashPrefix(0, sntrupHashPrefix(3, rho), c)
	}
	return sntrupHashPrefix(1, sntrupHashPrefix(3, rEnc), c)
}
