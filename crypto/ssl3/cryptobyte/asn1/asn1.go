// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package asn1 contains supporting types for parsing and building ASN.1
// messages with the cryptobyte package.
package asn1

import xasn1 "github.com/runZeroInc/excrypto/x/crypto/cryptobyte/asn1"

// Tag represents an ASN.1 identifier octet, consisting of a tag number
// (indicating a type) and class (such as context-specific or constructed).
type Tag = xasn1.Tag

const (
	BOOLEAN           = xasn1.BOOLEAN
	INTEGER           = xasn1.INTEGER
	BIT_STRING        = xasn1.BIT_STRING
	OCTET_STRING      = xasn1.OCTET_STRING
	NULL              = xasn1.NULL
	OBJECT_IDENTIFIER = xasn1.OBJECT_IDENTIFIER
	ENUM              = xasn1.ENUM
	UTF8String        = xasn1.UTF8String
	SEQUENCE          = xasn1.SEQUENCE
	SET               = xasn1.SET
	PrintableString   = xasn1.PrintableString
	T61String         = xasn1.T61String
	IA5String         = xasn1.IA5String
	UTCTime           = xasn1.UTCTime
	GeneralizedTime   = xasn1.GeneralizedTime
	GeneralString     = xasn1.GeneralString
)
