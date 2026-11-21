// Copyright (c) runZero, Inc.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"io"
	"math/big"
)

// This file implements the one finite-field Diffie-Hellman group a
// [Personality] can ask the server to serve: RFC 7919's ffdhe2048, as a TLS 1.3
// key exchange.
//
// No Go TLS implements the finite-field groups. That is a defensible choice for
// a general-purpose stack — they are slower than the curves and buy nothing —
// but it is visible from outside: a client that offers only ffdhe2048 is
// refused by every Go server and answered by almost every OpenSSL 3 one, and an
// active fingerprinter asks exactly that question. A server emulating OpenSSL
// has to be able to answer it.
//
// Nothing here is reachable without Personality.FFDHE2048: the group is not in
// this package's curve preference order, so it is never negotiated, never
// offered by the client half, and never seen by a caller that has not asked for
// it.

// ffdhe2048P is the RFC 7919 ffdhe2048 prime,
//
//	p = 2^2048 - 2^1984 + {[2^1918 * e] + 560316} * 2^64 - 1
//
// and ffdhe2048G its generator, 2. The prime is 2048 bits and safe: (p-1)/2 is
// prime, so every element other than 1 and p-1 generates a subgroup of order
// (p-1)/2 and the only small subgroup to keep a peer out of is {1, p-1}.
var (
	ffdhe2048P, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"+
			"D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"+
			"7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"+
			"2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"+
			"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"+
			"30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"+
			"B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"+
			"0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"+
			"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"+
			"3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"+
			"886B423861285C97FFFFFFFFFFFFFFFF", 16)
	ffdhe2048G = big.NewInt(2)
)

// ffdhe2048Size is the length of a key share in this group: the prime's size in
// bytes, which is what RFC 8446 Section 7.4.1 requires a share to be padded to.
const ffdhe2048Size = 256

// ffdheExponentBytes is the size of the private exponent. The group's subgroup
// order is (p-1)/2, so a full-length exponent is permitted, but RFC 7919
// Section 5.2 allows a short one of at least twice the target security level —
// 2048 bits of finite-field DH is worth about 103 bits, so 256 is comfortably
// above the floor, and it is also what OpenSSL uses for these groups.
const ffdheExponentBytes = 32

// ffdheKeyExchange is the server half of ffdhe2048.
//
// The client half is not implemented: this package never offers the group, and
// a key exchange it cannot have proposed is one it can never be asked to
// finish. Both client methods say so rather than returning something that would
// look like a key.
type ffdheKeyExchange struct{}

func (ffdheKeyExchange) keyShares(rand io.Reader) (*keySharePrivateKeys, []keyShare, error) {
	return nil, nil, errors.New("tls: ffdhe2048 is served, not offered")
}

func (ffdheKeyExchange) clientSharedSecret(*keySharePrivateKeys, []byte) ([]byte, error) {
	return nil, errors.New("tls: ffdhe2048 is served, not offered")
}

// serverSharedSecret validates the client's share, computes the shared secret
// and returns the server's own share.
func (ffdheKeyExchange) serverSharedSecret(rand io.Reader, clientKeyShare []byte) ([]byte, keyShare, error) {
	if len(clientKeyShare) != ffdhe2048Size {
		return nil, keyShare{}, errors.New("tls: ffdhe2048 key share has the wrong length")
	}
	peer := new(big.Int).SetBytes(clientKeyShare)
	// RFC 8446 Section 4.2.8.1: the peer's value must be strictly between 1 and
	// p-1, which in a safe-prime group rules out every small subgroup.
	if peer.Cmp(big.NewInt(1)) <= 0 || peer.Cmp(new(big.Int).Sub(ffdhe2048P, big.NewInt(1))) >= 0 {
		return nil, keyShare{}, errors.New("tls: ffdhe2048 key share is out of range")
	}

	priv := make([]byte, ffdheExponentBytes)
	if _, err := io.ReadFull(rand, priv); err != nil {
		return nil, keyShare{}, err
	}
	// Keep the exponent away from the handful of tiny values a bad random
	// source could produce; the cost is one bit of the exponent.
	priv[0] |= 0x80
	x := new(big.Int).SetBytes(priv)

	ours := new(big.Int).Exp(ffdhe2048G, x, ffdhe2048P)
	secret := new(big.Int).Exp(peer, x, ffdhe2048P)
	// A shared secret of 1 means the peer's value was in the small subgroup
	// after all; the range check above already excludes it, and this is the
	// belt to that braces.
	if secret.Cmp(big.NewInt(1)) == 0 {
		return nil, keyShare{}, errors.New("tls: ffdhe2048 shared secret is degenerate")
	}

	return ffdhePad(secret), keyShare{group: ffdhe2048Group, data: ffdhePad(ours)}, nil
}

// ffdhePad encodes n big-endian, left-padded with zeros to the size of the
// prime. RFC 8446 Section 7.4.1 requires both the key share and the shared
// secret to be that fixed length, which is not what [big.Int.Bytes] gives for a
// value with leading zero bytes.
func ffdhePad(n *big.Int) []byte {
	out := make([]byte, ffdhe2048Size)
	n.FillBytes(out)
	return out
}
