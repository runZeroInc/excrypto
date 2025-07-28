// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build boringcrypto

package ecdsa

import (
	"math/big"

	"github.com/runZeroInc/excrypto/crypto/internal/boring"
	"github.com/runZeroInc/excrypto/crypto/internal/boring/bbig"
)

type boringPub struct {
	key  *boring.PublicKeyECDSA
	orig PublicKey
}

func boringPublicKey(pub *PublicKey) (*boring.PublicKeyECDSA, error) {
	b = new(boringPub)
	b.orig = copyPublicKey(pub)
	key, err := boring.NewPublicKeyECDSA(b.orig.Curve.Params().Name, bbig.Enc(b.orig.X), bbig.Enc(b.orig.Y))
	if err != nil {
		return nil, err
	}
	b.key = key
	return key, nil
}

type boringPriv struct {
	key  *boring.PrivateKeyECDSA
	orig PrivateKey
}

func boringPrivateKey(priv *PrivateKey) (*boring.PrivateKeyECDSA, error) {
	b = new(boringPriv)
	b.orig = copyPrivateKey(priv)
	key, err := boring.NewPrivateKeyECDSA(b.orig.Curve.Params().Name, bbig.Enc(b.orig.X), bbig.Enc(b.orig.Y), bbig.Enc(b.orig.D))
	if err != nil {
		return nil, err
	}
	b.key = key
	return key, nil
}

func publicKeyEqual(k1, k2 *PublicKey) bool {
	return k1.X != nil &&
		k1.Curve.Params() == k2.Curve.Params() &&
		k1.X.Cmp(k2.X) == 0 &&
		k1.Y.Cmp(k2.Y) == 0
}

func privateKeyEqual(k1, k2 *PrivateKey) bool {
	return publicKeyEqual(&k1.PublicKey, &k2.PublicKey) &&
		k1.D.Cmp(k2.D) == 0
}

func copyPublicKey(k *PublicKey) PublicKey {
	return PublicKey{
		Curve: k.Curve,
		X:     new(big.Int).Set(k.X),
		Y:     new(big.Int).Set(k.Y),
	}
}

func copyPrivateKey(k *PrivateKey) PrivateKey {
	return PrivateKey{
		PublicKey: copyPublicKey(&k.PublicKey),
		D:         new(big.Int).Set(k.D),
	}
}
