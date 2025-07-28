// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"encoding/json"

	jsonKeys "github.com/runZeroInc/excrypto/crypto/json"
)

// SignatureAndHash is a SigAndHash that implements json.Marshaler and
// json.Unmarshaler
type SignatureAndHash SigAndHash

func (s *SigAndHash) ToSignatureAndHash() SignatureAndHash {
	return SignatureAndHash{s.Signature, s.Hash}
}

func SignatureAndHashFromSignatureScheme(inp SignatureScheme) SignatureAndHash {
	v := inp.Bytes()
	return SignatureAndHash{Signature: v[0], Hash: v[1]}
}

func SignatureAndHashesFromSignatureSchemes(inp []SignatureScheme) []SignatureAndHash {
	res := make([]SignatureAndHash, len(inp))
	for i, s := range inp {
		res[i] = SignatureAndHashFromSignatureScheme(s)
	}
	return res
}

func SignatureAndHashesToSignatureSchemes(inp []SignatureAndHash) []SignatureScheme {
	res := make([]SignatureScheme, len(inp))
	for i, s := range inp {
		res[i] = SignatureScheme(s.Signature)<<8 | SignatureScheme(s.Hash)
	}
	return res
}

type auxSignatureAndHash struct {
	SignatureAlgorithm string `json:"signature_algorithm"`
	HashAlgorithm      string `json:"hash_algorithm"`
}

// MarshalJSON implements the json.Marshaler interface
func (sh *SignatureAndHash) MarshalJSON() ([]byte, error) {
	aux := auxSignatureAndHash{
		SignatureAlgorithm: nameForSignature(sh.Signature),
		HashAlgorithm:      nameForHash(sh.Hash),
	}
	return json.Marshal(&aux)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (sh *SignatureAndHash) UnmarshalJSON(b []byte) error {
	aux := new(auxSignatureAndHash)
	if err := json.Unmarshal(b, aux); err != nil {
		return err
	}
	sh.Signature = signatureToName(aux.SignatureAlgorithm)
	sh.Hash = hashToName(aux.HashAlgorithm)
	return nil
}

func (ka *rsaKeyAgreement) RSAParams() *jsonKeys.RSAPublicKey {
	out := new(jsonKeys.RSAPublicKey)
	if ka.privateKey != nil {
		out.PublicKey = &ka.privateKey.PublicKey
	}
	return out
}

func (ka *ecdheKeyAgreement) ECDHParams() *jsonKeys.ECDHKeys {
	out := new(jsonKeys.ECDHKeys)
	out.TLSCurveID = jsonKeys.TLSCurveID(ka.curveID)
	if ka.key != nil {
		out.ServerPrivateKey = ka.key.Bytes()
		kb := ka.key.PublicKey().Bytes()
		out.ServerPublicKey = make([]byte, len(kb))
		copy(out.ServerPublicKey, kb)
	}
	return out
}

func (ka *ecdheKeyAgreement) ClientECDHParams() *jsonKeys.ECDHKeys {
	out := new(jsonKeys.ECDHKeys)
	out.TLSCurveID = jsonKeys.TLSCurveID(ka.curveID)
	if ka.key != nil {
		out.ClientPrivateKey = ka.key.Bytes()
		kb := ka.key.PublicKey().Bytes()
		out.ServerPublicKey = make([]byte, len(kb))
		copy(out.ServerPublicKey, kb)
	}
	return out
}
