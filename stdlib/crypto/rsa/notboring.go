// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa

import "github.com/runZeroInc/excrypto/stdlib/crypto/internal/boring"

func boringPublicKey(*PublicKey) (*boring.PublicKeyRSA, error) {
	panic("boringcrypto: not available")
}
func boringPrivateKey(*PrivateKey) (*boring.PrivateKeyRSA, error) {
	panic("boringcrypto: not available")
}
