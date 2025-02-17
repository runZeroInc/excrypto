// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as
// defined in [FIPS 186-5].
//
// Signatures generated by this package are not deterministic, but entropy is
// mixed with the private key and the message, achieving the same level of
// security in case of randomness source failure.
//
// Operations involving private keys are implemented using constant-time
// algorithms, as long as an [elliptic.Curve] returned by [elliptic.P224],
// [elliptic.P256], [elliptic.P384], or [elliptic.P521] is used.
//
// [FIPS 186-5]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
package ecdsa

import (
	"errors"
	"io"
	"math/big"

	"github.com/runZeroInc/excrypto/crypto"

	"github.com/runZeroInc/excrypto/crypto/ecdh"
	"github.com/runZeroInc/excrypto/crypto/elliptic"
	"github.com/runZeroInc/excrypto/crypto/internal/boring"
	"github.com/runZeroInc/excrypto/crypto/internal/boring/bbig"
	"github.com/runZeroInc/excrypto/crypto/internal/fips140/ecdsa"
	"github.com/runZeroInc/excrypto/crypto/internal/fips140hash"
	"github.com/runZeroInc/excrypto/crypto/internal/fips140only"
	"github.com/runZeroInc/excrypto/crypto/internal/randutil"
	"github.com/runZeroInc/excrypto/crypto/sha512"
	"github.com/runZeroInc/excrypto/crypto/subtle"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// PublicKey represents an ECDSA public key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// Any methods implemented on PublicKey might need to also be implemented on
// PrivateKey, as the latter embeds the former and will expose its methods.

// ECDH returns k as a [ecdh.PublicKey]. It returns an error if the key is
// invalid according to the definition of [ecdh.Curve.NewPublicKey], or if the
// Curve is not supported by crypto/ecdh.
func (k *PublicKey) ECDH() (*ecdh.PublicKey, error) {
	c := curveToECDH(k.Curve)
	if c == nil {
		return nil, errors.New("ecdsa: unsupported curve by crypto/ecdh")
	}
	if !k.Curve.IsOnCurve(k.X, k.Y) {
		return nil, errors.New("ecdsa: invalid public key")
	}
	return c.NewPublicKey(elliptic.Marshal(k.Curve, k.X, k.Y))
}

// Equal reports whether pub and x have the same value.
//
// Two keys are only considered to have the same value if they have the same Curve value.
// Note that for example [elliptic.P256] and elliptic.P256().Params() are different
// values, as the latter is a generic not constant time implementation.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return bigIntEqual(pub.X, xx.X) && bigIntEqual(pub.Y, xx.Y) &&
		// Standard library Curve implementations are singletons, so this check
		// will work for those. Other Curves might be equivalent even if not
		// singletons, but there is no definitive way to check for that, and
		// better to err on the side of safety.
		pub.Curve == xx.Curve
}

// PrivateKey represents an ECDSA private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// ECDH returns k as a [ecdh.PrivateKey]. It returns an error if the key is
// invalid according to the definition of [ecdh.Curve.NewPrivateKey], or if the
// Curve is not supported by [crypto/ecdh].
func (k *PrivateKey) ECDH() (*ecdh.PrivateKey, error) {
	c := curveToECDH(k.Curve)
	if c == nil {
		return nil, errors.New("ecdsa: unsupported curve by crypto/ecdh")
	}
	size := (k.Curve.Params().N.BitLen() + 7) / 8
	if k.D.BitLen() > size*8 {
		return nil, errors.New("ecdsa: invalid private key")
	}
	return c.NewPrivateKey(k.D.FillBytes(make([]byte, size)))
}

func curveToECDH(c elliptic.Curve) ecdh.Curve {
	switch c {
	case elliptic.P256():
		return ecdh.P256()
	case elliptic.P384():
		return ecdh.P384()
	case elliptic.P521():
		return ecdh.P521()
	default:
		return nil
	}
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// Equal reports whether priv and x have the same value.
//
// See [PublicKey.Equal] for details on how Curve is compared.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return priv.PublicKey.Equal(&xx.PublicKey) && bigIntEqual(priv.D, xx.D)
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
	return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}

// Sign signs a hash (which should be the result of hashing a larger message
// with opts.HashFunc()) using the private key, priv. If the hash is longer than
// the bit-length of the private key's curve order, the hash will be truncated
// to that length. It returns the ASN.1 encoded signature, like [SignASN1].
//
// If rand is not nil, the signature is randomized. Most applications should use
// [crypto/rand.Reader] as rand. Note that the returned signature does not
// depend deterministically on the bytes read from rand, and may change between
// calls and/or between versions.
//
// If rand is nil, Sign will produce a deterministic signature according to RFC
// 6979. When producing a deterministic signature, opts.HashFunc() must be the
// function used to produce digest and priv.Curve must be one of
// [elliptic.P224], [elliptic.P256], [elliptic.P384], or [elliptic.P521].
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if rand == nil {
		return signRFC6979(priv, digest, opts)
	}
	return SignASN1(rand, priv, digest)
}

// GenerateKey generates a new ECDSA private key for the specified curve.
//
// Most applications should use [crypto/rand.Reader] as rand. Note that the
// returned key does not depend deterministically on the bytes read from rand,
// and may change between calls and/or between versions.
func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
	randutil.MaybeReadByte(rand)

	if boring.Enabled && rand == boring.RandReader {
		x, y, d, err := boring.GenerateKeyECDSA(c.Params().Name)
		if err != nil {
			return nil, err
		}
		return &PrivateKey{PublicKey: PublicKey{Curve: c, X: bbig.Dec(x), Y: bbig.Dec(y)}, D: bbig.Dec(d)}, nil
	}
	boring.UnreachableExceptTests()

	switch c.Params() {
	case elliptic.P224().Params():
		return generateFIPS(c, ecdsa.P224(), rand)
	case elliptic.P256().Params():
		return generateFIPS(c, ecdsa.P256(), rand)
	case elliptic.P384().Params():
		return generateFIPS(c, ecdsa.P384(), rand)
	case elliptic.P521().Params():
		return generateFIPS(c, ecdsa.P521(), rand)
	default:
		return generateLegacy(c, rand)
	}
}

func generateFIPS[P ecdsa.Point[P]](curve elliptic.Curve, c *ecdsa.Curve[P], rand io.Reader) (*PrivateKey, error) {
	if fips140only.Enabled && !fips140only.ApprovedRandomReader(rand) {
		return nil, errors.New("crypto/ecdsa: only crypto/rand.Reader is allowed in FIPS 140-only mode")
	}
	privateKey, err := ecdsa.GenerateKey(c, rand)
	if err != nil {
		return nil, err
	}
	return privateKeyFromFIPS(curve, privateKey)
}

// errNoAsm is returned by signAsm and verifyAsm when the assembly
// implementation is not available.
var errNoAsm = errors.New("no assembly implementation available")

// SignASN1 signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the ASN.1 encoded signature.
//
// The signature is randomized. Most applications should use [crypto/rand.Reader]
// as rand. Note that the returned signature does not depend deterministically on
// the bytes read from rand, and may change between calls and/or between versions.
func SignASN1(rand io.Reader, priv *PrivateKey, hash []byte) ([]byte, error) {
	randutil.MaybeReadByte(rand)

	if boring.Enabled && rand == boring.RandReader {
		b, err := boringPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return boring.SignMarshalECDSA(b, hash)
	}
	boring.UnreachableExceptTests()

	switch priv.Curve.Params() {
	case elliptic.P224().Params():
		return signFIPS(ecdsa.P224(), priv, rand, hash)
	case elliptic.P256().Params():
		return signFIPS(ecdsa.P256(), priv, rand, hash)
	case elliptic.P384().Params():
		return signFIPS(ecdsa.P384(), priv, rand, hash)
	case elliptic.P521().Params():
		return signFIPS(ecdsa.P521(), priv, rand, hash)
	default:
		return signLegacy(priv, rand, hash)
	}
}

func signFIPS[P ecdsa.Point[P]](c *ecdsa.Curve[P], priv *PrivateKey, rand io.Reader, hash []byte) ([]byte, error) {
	if fips140only.Enabled && !fips140only.ApprovedRandomReader(rand) {
		return nil, errors.New("crypto/ecdsa: only crypto/rand.Reader is allowed in FIPS 140-only mode")
	}
	// privateKeyToFIPS is very slow in FIPS mode because it performs a
	// Sign+Verify cycle per FIPS 140-3 IG 10.3.A. We should find a way to cache
	// it or attach it to the PrivateKey.
	k, err := privateKeyToFIPS(c, priv)
	if err != nil {
		return nil, err
	}
	// Always using SHA-512 instead of the hash that computed hash is
	// technically a violation of draft-irtf-cfrg-det-sigs-with-noise-04 but in
	// our API we don't get to know what it was, and this has no security impact.
	sig, err := ecdsa.Sign(c, sha512.New, k, rand, hash)
	if err != nil {
		return nil, err
	}
	return encodeSignature(sig.R, sig.S)
}

func signRFC6979(priv *PrivateKey, hash []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, errors.New("ecdsa: Sign called with nil opts")
	}
	h := opts.HashFunc()
	if h.Size() != len(hash) {
		return nil, errors.New("ecdsa: hash length does not match hash function")
	}
	switch priv.Curve.Params() {
	case elliptic.P224().Params():
		return signFIPSDeterministic(ecdsa.P224(), h, priv, hash)
	case elliptic.P256().Params():
		return signFIPSDeterministic(ecdsa.P256(), h, priv, hash)
	case elliptic.P384().Params():
		return signFIPSDeterministic(ecdsa.P384(), h, priv, hash)
	case elliptic.P521().Params():
		return signFIPSDeterministic(ecdsa.P521(), h, priv, hash)
	default:
		return nil, errors.New("ecdsa: curve not supported by deterministic signatures")
	}
}

func signFIPSDeterministic[P ecdsa.Point[P]](c *ecdsa.Curve[P], hashFunc crypto.Hash, priv *PrivateKey, hash []byte) ([]byte, error) {
	k, err := privateKeyToFIPS(c, priv)
	if err != nil {
		return nil, err
	}
	h := fips140hash.UnwrapNew(hashFunc.New)
	if fips140only.Enabled && !fips140only.ApprovedHash(h()) {
		return nil, errors.New("crypto/ecdsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode")
	}
	sig, err := ecdsa.SignDeterministic(c, h, k, hash)
	if err != nil {
		return nil, err
	}
	return encodeSignature(sig.R, sig.S)
}

func encodeSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

// addASN1IntBytes encodes in ASN.1 a positive integer represented as
// a big-endian byte slice with zero or more leading zeroes.
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

// VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
//
// The inputs are not considered confidential, and may leak through timing side
// channels, or if an attacker has control of part of the inputs.
func VerifyASN1(pub *PublicKey, hash, sig []byte) bool {
	if boring.Enabled {
		key, err := boringPublicKey(pub)
		if err != nil {
			return false
		}
		return boring.VerifyECDSA(key, hash, sig)
	}
	boring.UnreachableExceptTests()

	switch pub.Curve.Params() {
	case elliptic.P224().Params():
		return verifyFIPS(ecdsa.P224(), pub, hash, sig)
	case elliptic.P256().Params():
		return verifyFIPS(ecdsa.P256(), pub, hash, sig)
	case elliptic.P384().Params():
		return verifyFIPS(ecdsa.P384(), pub, hash, sig)
	case elliptic.P521().Params():
		return verifyFIPS(ecdsa.P521(), pub, hash, sig)
	default:
		return verifyLegacy(pub, hash, sig)
	}
}

func verifyFIPS[P ecdsa.Point[P]](c *ecdsa.Curve[P], pub *PublicKey, hash, sig []byte) bool {
	r, s, err := parseSignature(sig)
	if err != nil {
		return false
	}
	k, err := publicKeyToFIPS(c, pub)
	if err != nil {
		return false
	}
	if err := ecdsa.Verify(c, k, hash, &ecdsa.Signature{R: r, S: s}); err != nil {
		return false
	}
	return true
}

func parseSignature(sig []byte) (r, s []byte, err error) {
	var inner cryptobyte.String
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&r) ||
		!inner.ReadASN1Integer(&s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1")
	}
	return r, s, nil
}

func publicKeyFromFIPS(curve elliptic.Curve, pub *ecdsa.PublicKey) (*PublicKey, error) {
	x, y, err := pointToAffine(curve, pub.Bytes())
	if err != nil {
		return nil, err
	}
	return &PublicKey{Curve: curve, X: x, Y: y}, nil
}

func privateKeyFromFIPS(curve elliptic.Curve, priv *ecdsa.PrivateKey) (*PrivateKey, error) {
	pub, err := publicKeyFromFIPS(curve, priv.PublicKey())
	if err != nil {
		return nil, err
	}
	return &PrivateKey{PublicKey: *pub, D: new(big.Int).SetBytes(priv.Bytes())}, nil
}

func publicKeyToFIPS[P ecdsa.Point[P]](c *ecdsa.Curve[P], pub *PublicKey) (*ecdsa.PublicKey, error) {
	Q, err := pointFromAffine(pub.Curve, pub.X, pub.Y)
	if err != nil {
		return nil, err
	}
	return ecdsa.NewPublicKey(c, Q)
}

func privateKeyToFIPS[P ecdsa.Point[P]](c *ecdsa.Curve[P], priv *PrivateKey) (*ecdsa.PrivateKey, error) {
	Q, err := pointFromAffine(priv.Curve, priv.X, priv.Y)
	if err != nil {
		return nil, err
	}
	return ecdsa.NewPrivateKey(c, priv.D.Bytes(), Q)
}

// pointFromAffine is used to convert the PublicKey to a nistec SetBytes input.
func pointFromAffine(curve elliptic.Curve, x, y *big.Int) ([]byte, error) {
	bitSize := curve.Params().BitSize
	// Reject values that would not get correctly encoded.
	if x.Sign() < 0 || y.Sign() < 0 {
		return nil, errors.New("negative coordinate")
	}
	if x.BitLen() > bitSize || y.BitLen() > bitSize {
		return nil, errors.New("overflowing coordinate")
	}
	// Encode the coordinates and let SetBytes reject invalid points.
	byteLen := (bitSize + 7) / 8
	buf := make([]byte, 1+2*byteLen)
	buf[0] = 4 // uncompressed point
	x.FillBytes(buf[1 : 1+byteLen])
	y.FillBytes(buf[1+byteLen : 1+2*byteLen])
	return buf, nil
}

// pointToAffine is used to convert a nistec Bytes encoding to a PublicKey.
func pointToAffine(curve elliptic.Curve, p []byte) (x, y *big.Int, err error) {
	if len(p) == 1 && p[0] == 0 {
		// This is the encoding of the point at infinity.
		return nil, nil, errors.New("ecdsa: public key point is the infinity")
	}
	byteLen := (curve.Params().BitSize + 7) / 8
	x = new(big.Int).SetBytes(p[1 : 1+byteLen])
	y = new(big.Int).SetBytes(p[1+byteLen:])
	return x, y, nil
}
