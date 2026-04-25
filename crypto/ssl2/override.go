// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssl2

import (
	"os"
	"strconv"
)

// overrideCipher lets tests force a particular cipher kind via the
// SSL2_FORCE_CIPHER environment variable (decimal or 0xHEX). Returns 0 if
// unset.
func overrideCipher() CipherKind {
	v := os.Getenv("SSL2_FORCE_CIPHER")
	if v == "" {
		return 0
	}
	switch v {
	case "rc4":
		return CK_RC4_128_WITH_MD5
	case "rc4_export":
		return CK_RC4_128_EXPORT40_WITH_MD5
	case "rc2":
		return CK_RC2_128_CBC_WITH_MD5
	case "rc2_export":
		return CK_RC2_128_CBC_EXPORT40_WITH_MD5
	case "des":
		return CK_DES_64_CBC_WITH_MD5
	case "3des":
		return CK_DES_192_EDE3_CBC_WITH_MD5
	case "idea":
		return CK_IDEA_128_CBC_WITH_MD5
	}
	if n, err := strconv.ParseUint(v, 0, 32); err == nil {
		return CipherKind(n)
	}
	return 0
}
