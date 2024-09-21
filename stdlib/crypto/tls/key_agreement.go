// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"io"
	"math/big"

	"github.com/runZeroInc/excrypto/stdlib/crypto"
	"github.com/runZeroInc/excrypto/stdlib/crypto/dsa"
	"github.com/runZeroInc/excrypto/stdlib/crypto/ecdh"
	"github.com/runZeroInc/excrypto/stdlib/crypto/ecdsa"
	"github.com/runZeroInc/excrypto/stdlib/crypto/elliptic"
	"github.com/runZeroInc/excrypto/stdlib/crypto/md5"
	"github.com/runZeroInc/excrypto/stdlib/crypto/rsa"
	"github.com/runZeroInc/excrypto/stdlib/crypto/sha1"
	"github.com/runZeroInc/excrypto/stdlib/crypto/x509"
	"github.com/runZeroInc/excrypto/stdlib/encoding/asn1"
)

// A keyAgreement implements the client and server side of a TLS 1.0–1.2 key
// agreement protocol by generating and processing key exchange messages.
type keyAgreement interface {
	// On the server side, the first two methods are called in order.

	// In the case that the key agreement protocol doesn't use a
	// ServerKeyExchange message, generateServerKeyExchange can return nil,
	// nil.
	generateServerKeyExchange(*Config, *Certificate, *clientHelloMsg, *serverHelloMsg) (*serverKeyExchangeMsg, error)
	processClientKeyExchange(*Config, *Certificate, *clientKeyExchangeMsg, uint16) ([]byte, error)

	// On the client side, the next two methods are called in order.

	// This method may not be called if the server doesn't send a
	// ServerKeyExchange message.
	processServerKeyExchange(*Config, *clientHelloMsg, *serverHelloMsg, *x509.Certificate, *serverKeyExchangeMsg) error
	generateClientKeyExchange(*Config, *clientHelloMsg, *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error)
}

var errClientKeyExchange = errors.New("tls: invalid ClientKeyExchange message")
var errServerKeyExchange = errors.New("tls: invalid ServerKeyExchange message")

// rsaKeyAgreement implements the standard TLS key agreement where the client
// encrypts the pre-master secret to the server's public key.
type rsaKeyAgreement struct {
	version    uint16
	privateKey *rsa.PrivateKey
}

func (ka rsaKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, nil
}

func (ka rsaKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) < 2 {
		return nil, errClientKeyExchange
	}
	ciphertextLen := int(ckx.ciphertext[0])<<8 | int(ckx.ciphertext[1])
	if ciphertextLen != len(ckx.ciphertext)-2 {
		return nil, errClientKeyExchange
	}
	ciphertext := ckx.ciphertext[2:]

	priv, ok := cert.PrivateKey.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Decrypter")
	}
	// Perform constant time RSA PKCS #1 v1.5 decryption
	preMasterSecret, err := priv.Decrypt(config.rand(), ciphertext, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 48})
	if err != nil {
		return nil, err
	}

	// zcrypto
	ka.privateKey = cert.PrivateKey.(*rsa.PrivateKey)
	ka.version = version

	// We don't check the version number in the premaster secret. For one,
	// by checking it, we would leak information about the validity of the
	// encrypted pre-master secret. Secondly, it provides only a small
	// benefit against a downgrade attack and some implementations send the
	// wrong version anyway. See the discussion at the end of section
	// 7.4.7.1 of RFC 4346.
	return preMasterSecret, nil
}

func (ka rsaKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	return errors.New("tls: unexpected ServerKeyExchange")
}

func (ka rsaKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = byte(clientHello.vers >> 8)
	preMasterSecret[1] = byte(clientHello.vers)
	_, err := io.ReadFull(config.rand(), preMasterSecret[2:])
	if err != nil {
		return nil, nil, err
	}

	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("tls: server certificate contains incorrect key type for selected ciphersuite")
	}
	encrypted, err := rsa.EncryptPKCS1v15(config.rand(), rsaKey, preMasterSecret)
	if err != nil {
		return nil, nil, err
	}
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, len(encrypted)+2)
	ckx.ciphertext[0] = byte(len(encrypted) >> 8)
	ckx.ciphertext[1] = byte(len(encrypted))
	copy(ckx.ciphertext[2:], encrypted)
	return preMasterSecret, ckx, nil
}

// sha1Hash calculates a SHA1 hash over the given byte slices.
func sha1Hash(slices [][]byte) []byte {
	hsha1 := sha1.New()
	for _, slice := range slices {
		hsha1.Write(slice)
	}
	return hsha1.Sum(nil)
}

// md5SHA1Hash implements TLS 1.0's hybrid hash function which consists of the
// concatenation of an MD5 and SHA1 hash.
func md5SHA1Hash(slices [][]byte) []byte {
	md5sha1 := make([]byte, md5.Size+sha1.Size)
	hmd5 := md5.New()
	for _, slice := range slices {
		hmd5.Write(slice)
	}
	copy(md5sha1, hmd5.Sum(nil))
	copy(md5sha1[md5.Size:], sha1Hash(slices))
	return md5sha1
}

// hashForServerKeyExchange hashes the given slices and returns their digest
// using the given hash function (for TLS 1.2) or using a default based on
// the sigType (for earlier TLS versions). For Ed25519 signatures, which don't
// do pre-hashing, it returns the concatenation of the slices.
func hashForServerKeyExchange(sigType uint8, hashFunc crypto.Hash, version uint16, slices ...[]byte) []byte {
	if sigType == signatureEd25519 {
		var signed []byte
		for _, slice := range slices {
			signed = append(signed, slice...)
		}
		return signed
	}
	if version >= VersionTLS12 {
		h := hashFunc.New()
		for _, slice := range slices {
			h.Write(slice)
		}
		digest := h.Sum(nil)
		return digest
	}
	if sigType == signatureECDSA {
		return sha1Hash(slices)
	}
	return md5SHA1Hash(slices)
}

// keyAgreementAuthentication is a helper interface that specifies how
// to authenticate the ServerKeyExchange parameters.
type keyAgreementAuthentication interface {
	signParameters(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg, params []byte) (*serverKeyExchangeMsg, error)
	verifyParameters(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, params []byte, sig []byte) ([]byte, error)
}

// nilKeyAgreementAuthentication does not authenticate the key
// agreement parameters.
type nilKeyAgreementAuthentication struct{}

func (ka *nilKeyAgreementAuthentication) signParameters(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg, params []byte) (*serverKeyExchangeMsg, error) {
	skx := new(serverKeyExchangeMsg)
	skx.key = params
	return skx, nil
}

func (ka *nilKeyAgreementAuthentication) verifyParameters(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, params []byte, sig []byte) ([]byte, error) {
	return nil, nil
}

// pickTLS12HashForSignature returns a TLS 1.2 hash identifier for signing a
// ServerKeyExchange given the signature type being used and the client's
// advertised list of supported signature and hash combinations.
func pickTLS12HashForSignature(sigType uint8, clientList, serverList []SigAndHash) (uint8, error) {
	if len(clientList) == 0 {
		// If the client didn't specify any signature_algorithms
		// extension then we can assume that it supports SHA1. See
		// http://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
		return hashSHA1, nil
	}

	for _, sigAndHash := range clientList {
		if sigAndHash.Signature != sigType {
			continue
		}
		if isSupportedSignatureAndHash(sigAndHash, serverList) {
			return sigAndHash.Hash, nil
		}
	}

	return 0, errors.New("tls: client doesn't support any common hash functions")
}

// signedKeyAgreement signs the ServerKeyExchange parameters with the
// server's private key.
type signedKeyAgreement struct {
	version uint16
	sigType uint8
	raw     []byte
	valid   bool
	sh      SigAndHash
}

func (ka *signedKeyAgreement) signParameters(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg, params []byte) (*serverKeyExchangeMsg, error) {
	var tlsHashID uint8
	var err error
	if ka.version >= VersionTLS12 {
		if tlsHashID, err = pickTLS12HashForSignature(ka.sigType, clientHello.signatureAndHashes, config.signatureAndHashesForServer()); err != nil {
			return nil, err
		}
		ka.sh.Hash = tlsHashID
	}
	ka.sh.Signature = ka.sigType
	digest := hashForServerKeyExchange(ka.sigType, crypto.Hash(tlsHashID), ka.version, clientHello.random, hello.random, params)
	var sig []byte
	switch ka.sigType {
	case signatureECDSA:
		privKey, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("ECDHE ECDSA requires an ECDSA server private key")
		}
		r, s, err := ecdsa.Sign(config.rand(), privKey, digest)
		if err != nil {
			return nil, errors.New("failed to sign ECDHE parameters: " + err.Error())
		}
		sig, err = asn1.Marshal(ecdsaSignature{r, s})
		if err != nil {
			return nil, errors.New("failed to marshal ECDSA signature: " + err.Error())
		}
	case signatureRSA:
		privKey, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("ECDHE RSA requires a RSA server private key")
		}
		sig, err = rsa.SignPKCS1v15(config.rand(), privKey, crypto.Hash(tlsHashID), digest)
		if err != nil {
			return nil, errors.New("failed to sign ECDHE parameters: " + err.Error())
		}
	default:
		return nil, errors.New("unknown ECDHE signature algorithm")
	}

	skx := new(serverKeyExchangeMsg)
	skx.digest = digest
	sigAndHashLen := 0
	if ka.version >= VersionTLS12 {
		sigAndHashLen = 2
	}
	skx.key = make([]byte, len(params)+sigAndHashLen+2+len(sig))
	copy(skx.key, params)
	k := skx.key[len(params):]
	if ka.version >= VersionTLS12 {
		k[0] = tlsHashID
		k[1] = ka.sigType
		k = k[2:]
	}
	k[0] = byte(len(sig) >> 8)
	k[1] = byte(len(sig))
	copy(k[2:], sig)
	ka.raw = sig
	ka.valid = true // We (the server) signed
	return skx, nil
}

func (ka *signedKeyAgreement) verifyParameters(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, params []byte, sig []byte) ([]byte, error) {
	if len(sig) < 2 {
		return nil, errServerKeyExchange
	}

	var tlsHashID uint8
	if ka.version >= VersionTLS12 {
		// handle SignatureAndHashAlgorithm
		var sigAndHash []uint8
		sigAndHash, sig = sig[:2], sig[2:]
		tlsHashID = sigAndHash[0]
		ka.sh.Hash = tlsHashID
		ka.sh.Signature = sigAndHash[1]
		if sigAndHash[1] != ka.sigType {
			return nil, errServerKeyExchange
		}
		if len(sig) < 2 {
			return nil, errServerKeyExchange
		}

		if !isSupportedSignatureAndHash(SigAndHash{ka.sigType, tlsHashID}, config.signatureAndHashesForClient()) {
			return nil, errors.New("tls: unsupported hash function for ServerKeyExchange")
		}
	}
	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return nil, errServerKeyExchange
	}
	sig = sig[2:]
	ka.raw = sig

	digest := hashForServerKeyExchange(ka.sigType, crypto.Hash(tlsHashID), ka.version, clientHello.random, serverHello.random, params)
	switch ka.sigType {
	case signatureECDSA:
		augECDSA, ok := cert.PublicKey.(*x509.AugmentedECDSA)
		if !ok {
			return digest, errors.New("ECDHE ECDSA: could not covert cert.PublicKey to x509.AugmentedECDSA")
		}
		pubKey := augECDSA.Pub
		ecdsaSig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(sig, ecdsaSig); err != nil {
			return digest, err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return digest, errors.New("ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pubKey, digest, ecdsaSig.R, ecdsaSig.S) {
			return digest, errors.New("ECDSA verification failure")
		}
	case signatureRSA:
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return digest, errors.New("ECDHE RSA requires a RSA server public key")
		}
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.Hash(tlsHashID), digest, sig); err != nil {
			return digest, err
		}
	case signatureDSA:
		pubKey, ok := cert.PublicKey.(*dsa.PublicKey)
		if !ok {
			return digest, errors.New("DSS ciphers require a DSA server public key")
		}
		dsaSig := new(dsaSignature)
		if _, err := asn1.Unmarshal(sig, dsaSig); err != nil {
			return digest, err
		}
		if dsaSig.R.Sign() <= 0 || dsaSig.S.Sign() <= 0 {
			return digest, errors.New("DSA signature contained zero or negative values")
		}
		if !dsa.Verify(pubKey, digest, dsaSig.R, dsaSig.S) {
			return digest, errors.New("DSA verification failure")
		}
	default:
		return digest, errors.New("unknown ECDHE signature algorithm")
	}
	ka.valid = true
	return digest, nil
}

// ecdheKeyAgreement implements a TLS key agreement where the server
// generates an ephemeral EC public/private key pair and signs it. The
// pre-master secret is then calculated using ECDH. The signature may
// be ECDSA, Ed25519 or RSA.
type ecdheKeyAgreement struct {
	version uint16
	isRSA   bool
	key     *ecdh.PrivateKey

	// ckx and preMasterSecret are generated in processServerKeyExchange
	// and returned in generateClientKeyExchange.
	ckx             *clientKeyExchangeMsg
	preMasterSecret []byte

	// zcrypto
	auth          keyAgreementAuthentication
	privateKey    []byte
	curve         elliptic.Curve
	x, y          *big.Int
	verifyError   error
	curveID       uint16
	clientPrivKey []byte
	serverPrivKey []byte
	clientX       *big.Int
	clientY       *big.Int
}

func ellipticCurveForCurveID(id CurveID) (elliptic.Curve, bool) {
	switch id {
	case CurveP256:
		return elliptic.P256(), true
	case CurveP384:
		return elliptic.P384(), true
	case CurveP521:
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

func (ka *ecdheKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	var curveid CurveID
	preferredCurves := config.curvePreferences(clientHello.vers)

NextCandidate:
	for _, candidate := range preferredCurves {
		for _, c := range clientHello.supportedCurves {
			if candidate == c {
				curveid = c
				break NextCandidate
			}
		}
	}

	if curveid == 0 {
		return nil, errors.New("tls: no supported elliptic curves offered")
	}
	ka.curveID = uint16(curveid)

	var ok bool
	if ka.curve, ok = ellipticCurveForCurveID(curveid); !ok {
		return nil, errors.New("tls: preferredCurves includes unsupported curve")
	}

	var err error
	ka.privateKey, ka.x, ka.y, err = elliptic.GenerateKey(ka.curve, config.rand())
	if err != nil {
		return nil, err
	}
	ecdhePublic := elliptic.Marshal(ka.curve, ka.x, ka.y)

	ka.serverPrivKey = make([]byte, len(ka.privateKey))
	copy(ka.serverPrivKey, ka.privateKey)

	// http://tools.ietf.org/html/rfc4492#section-5.4
	serverECDHParams := make([]byte, 1+2+1+len(ecdhePublic))
	serverECDHParams[0] = 3 // named curve
	serverECDHParams[1] = byte(curveid >> 8)
	serverECDHParams[2] = byte(curveid)
	serverECDHParams[3] = byte(len(ecdhePublic))
	copy(serverECDHParams[4:], ecdhePublic)

	return ka.auth.signParameters(config, cert, clientHello, hello, serverECDHParams)
}

func (ka *ecdheKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) == 0 || int(ckx.ciphertext[0]) != len(ckx.ciphertext)-1 {
		return nil, errClientKeyExchange
	}
	ka.clientX, ka.clientY = elliptic.Unmarshal(ka.curve, ckx.ciphertext[1:])
	if ka.clientX == nil {
		return nil, errClientKeyExchange
	}
	ka.version = version

	sharedX, _ := ka.curve.ScalarMult(ka.clientX, ka.clientY, ka.privateKey)
	preMasterSecret := make([]byte, (ka.curve.Params().BitSize+7)>>3)
	xBytes := sharedX.Bytes()
	copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)

	return preMasterSecret, nil
}

func (ka *ecdheKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(skx.key) < 4 {
		return errServerKeyExchange
	}
	if skx.key[0] != 3 { // named curve
		return errors.New("tls: server selected unsupported curve")
	}
	curveid := CurveID(skx.key[1])<<8 | CurveID(skx.key[2])
	ka.curveID = uint16(curveid)

	var ok bool
	if ka.curve, ok = ellipticCurveForCurveID(curveid); !ok {
		return errors.New("tls: server selected unsupported curve")
	}

	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}
	ka.x, ka.y = elliptic.Unmarshal(ka.curve, skx.key[4:4+publicLen])
	if ka.x == nil {
		return errServerKeyExchange
	}
	serverECDHParams := skx.key[:4+publicLen]

	sig := skx.key[4+publicLen:]
	skx.digest, ka.verifyError = ka.auth.verifyParameters(config, clientHello, serverHello, cert, serverECDHParams, sig)
	if config.InsecureSkipVerify {
		return nil
	}
	return ka.verifyError
}

func (ka *ecdheKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.curve == nil {
		return nil, nil, errors.New("missing ServerKeyExchange message")
	}
	priv, mx, my, err := elliptic.GenerateKey(ka.curve, config.rand())
	if err != nil {
		return nil, nil, err
	}

	ka.clientPrivKey = make([]byte, len(priv))
	copy(ka.clientPrivKey, priv)
	ka.clientX = mx
	ka.clientY = my

	x, _ := ka.curve.ScalarMult(ka.x, ka.y, priv)
	preMasterSecret := make([]byte, (ka.curve.Params().BitSize+7)>>3)
	xBytes := x.Bytes()
	copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)

	serialized := elliptic.Marshal(ka.curve, mx, my)

	ckx := new(clientKeyExchangeMsg)
	var body []byte
	ckx.ciphertext = make([]byte, 1+len(serialized))
	ckx.ciphertext[0] = byte(len(serialized))
	body = ckx.ciphertext[1:]
	copy(body, serialized)

	return preMasterSecret, ckx, nil
}

// Go stdlib
/*
func (ka *ecdheKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	var curveID CurveID
	for _, c := range clientHello.supportedCurves {
		if config.supportsCurve(ka.version, c) {
			curveID = c
			break
		}
	}

	if curveID == 0 {
		return nil, errors.New("tls: no supported elliptic curves offered")
	}
	ka.curveID = ka.curveID

	if _, ok := curveForCurveID(curveID); !ok {
		return nil, errors.New("tls: CurvePreferences includes unsupported curve")
	}

	key, err := generateECDHEKey(config.rand(), curveID)
	if err != nil {
		return nil, err
	}
	ka.key = key

	// See RFC 4492, Section 5.4.
	ecdhePublic := key.PublicKey().Bytes()
	serverECDHEParams := make([]byte, 1+2+1+len(ecdhePublic))
	serverECDHEParams[0] = 3 // named curve
	serverECDHEParams[1] = byte(curveID >> 8)
	serverECDHEParams[2] = byte(curveID)
	serverECDHEParams[3] = byte(len(ecdhePublic))
	copy(serverECDHEParams[4:], ecdhePublic)

	priv, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("tls: certificate private key of type %T does not implement crypto.Signer", cert.PrivateKey)
	}

	var signatureAlgorithm SignatureScheme
	var sigType uint8
	var sigHash crypto.Hash
	if ka.version >= VersionTLS12 {
		signatureAlgorithm, err = selectSignatureScheme(ka.version, cert, clientHello.supportedSignatureAlgorithms)
		if err != nil {
			return nil, err
		}
		sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
		if err != nil {
			return nil, err
		}
	} else {
		sigType, sigHash, err = legacyTypeAndHashFromPublicKey(priv.Public())
		if err != nil {
			return nil, err
		}
	}
	if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
		return nil, errors.New("tls: certificate cannot be used with the selected cipher suite")
	}

	signed := hashForServerKeyExchange(sigType, sigHash, ka.version, clientHello.random, hello.random, serverECDHEParams)

	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := priv.Sign(config.rand(), signed, signOpts)
	if err != nil {
		return nil, errors.New("tls: failed to sign ECDHE parameters: " + err.Error())
	}

	skx := new(serverKeyExchangeMsg)
	sigAndHashLen := 0
	if ka.version >= VersionTLS12 {
		sigAndHashLen = 2
	}
	skx.key = make([]byte, len(serverECDHEParams)+sigAndHashLen+2+len(sig))
	copy(skx.key, serverECDHEParams)
	k := skx.key[len(serverECDHEParams):]
	if ka.version >= VersionTLS12 {
		k[0] = byte(signatureAlgorithm >> 8)
		k[1] = byte(signatureAlgorithm)
		k = k[2:]
	}
	k[0] = byte(len(sig) >> 8)
	k[1] = byte(len(sig))
	copy(k[2:], sig)

	return skx, nil
}

func (ka *ecdheKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) == 0 || int(ckx.ciphertext[0]) != len(ckx.ciphertext)-1 {
		return nil, errClientKeyExchange
	}

	peerKey, err := ka.key.Curve().NewPublicKey(ckx.ciphertext[1:])
	if err != nil {
		return nil, errClientKeyExchange
	}
	preMasterSecret, err := ka.key.ECDH(peerKey)
	if err != nil {
		return nil, errClientKeyExchange
	}

	return preMasterSecret, nil
}

func (ka *ecdheKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(skx.key) < 4 {
		return errServerKeyExchange
	}
	if skx.key[0] != 3 { // named curve
		return errors.New("tls: server selected unsupported curve")
	}
	curveID := CurveID(skx.key[1])<<8 | CurveID(skx.key[2])

	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}
	serverECDHEParams := skx.key[:4+publicLen]
	publicKey := serverECDHEParams[4:]

	sig := skx.key[4+publicLen:]
	if len(sig) < 2 {
		return errServerKeyExchange
	}

	if _, ok := curveForCurveID(curveID); !ok {
		return errors.New("tls: server selected unsupported curve")
	}

	key, err := generateECDHEKey(config.rand(), curveID)
	if err != nil {
		return err
	}
	ka.key = key

	peerKey, err := key.Curve().NewPublicKey(publicKey)
	if err != nil {
		return errServerKeyExchange
	}
	ka.preMasterSecret, err = key.ECDH(peerKey)
	if err != nil {
		return errServerKeyExchange
	}

	ourPublicKey := key.PublicKey().Bytes()
	ka.ckx = new(clientKeyExchangeMsg)
	ka.ckx.ciphertext = make([]byte, 1+len(ourPublicKey))
	ka.ckx.ciphertext[0] = byte(len(ourPublicKey))
	copy(ka.ckx.ciphertext[1:], ourPublicKey)

	var sigType uint8
	var sigHash crypto.Hash
	if ka.version >= VersionTLS12 {
		signatureAlgorithm := SignatureScheme(sig[0])<<8 | SignatureScheme(sig[1])
		sig = sig[2:]
		if len(sig) < 2 {
			return errServerKeyExchange
		}

		if !isSupportedSignatureAlgorithm(signatureAlgorithm, clientHello.supportedSignatureAlgorithms) {
			return errors.New("tls: certificate used with invalid signature algorithm")
		}
		sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
		if err != nil {
			return err
		}
	} else {
		sigType, sigHash, err = legacyTypeAndHashFromPublicKey(cert.PublicKey)
		if err != nil {
			return err
		}
	}
	if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
		return errServerKeyExchange
	}

	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return errServerKeyExchange
	}
	sig = sig[2:]

	signed := hashForServerKeyExchange(sigType, sigHash, ka.version, clientHello.random, serverHello.random, serverECDHEParams)
	if err := verifyHandshakeSignature(sigType, cert.PublicKey, sigHash, signed, sig); err != nil {
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}
	return nil
}

func (ka *ecdheKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.ckx == nil {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}

	return ka.preMasterSecret, ka.ckx, nil
}
*/
