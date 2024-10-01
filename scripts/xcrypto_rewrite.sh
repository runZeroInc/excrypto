#!/bin/bash

DIR=$1

if [[ "${DIR}" == "" ]]; then
    echo "missing directory argument"
    exit 1
fi

find ${DIR}/ -type f -exec sed -i '' -e 's@golang.org/x/crypto@github.com/runZeroInc/excrypto/x/crypto@g' {} \;
rm -f ${DIR}/go.mod ${DIR}/go.sum
rm -rf ${DIR}/acme/
rm -rf x/crypto.upstream/.git
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto"@"github.com/runZeroInc/excrypto/crypto"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/subtle"@"github.com/runZeroInc/excrypto/crypto/subtle"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"encoding/asn1"@"github.com/runZeroInc/excrypto/encoding/asn1"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/cipher"@"github.com/runZeroInc/excrypto/crypto/cipher"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/dsa"@"github.com/runZeroInc/excrypto/crypto/dsa"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/rsa"@"github.com/runZeroInc/excrypto/crypto/rsa"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/x509@"github.com/runZeroInc/excrypto/crypto/x509@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/aes"@"github.com/runZeroInc/excrypto/crypto/aes"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/des"@"github.com/runZeroInc/excrypto/crypto/des"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/rc4"@"github.com/runZeroInc/excrypto/crypto/rc4"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/hmac"@"github.com/runZeroInc/excrypto/crypto/hmac"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/md5"@"github.com/runZeroInc/excrypto/crypto/md5"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/sha1"@"github.com/runZeroInc/excrypto/crypto/sha1"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/sha256"@"github.com/runZeroInc/excrypto/crypto/sha256"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/sha384"@"github.com/runZeroInc/excrypto/crypto/sha384"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/sha512"@"github.com/runZeroInc/excrypto/crypto/sha512"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/ecdsa"@"github.com/runZeroInc/excrypto/crypto/ecdsa"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/elliptic"@"github.com/runZeroInc/excrypto/crypto/elliptic"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@"crypto/ed25519"@"github.com/runZeroInc/excrypto/crypto/ed25519"@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@return "github.com/runZeroInc/excrypto/x/crypto@"x/crypto@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@errors.New("github.com/runZeroInc/excrypto/x/crypto@errors.New("x/crypto@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@fmt.Errorf("github.com/runZeroInc/excrypto/x/crypto@fmt.Errorf("x/crypto@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@fmt.Sprintf("github.com/runZeroInc/excrypto/x/crypto@fmt.Sprintf("x/crypto@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@return "github.com/runZeroInc/excrypto/x/crypto@"crypto@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@errors.New("github.com/runZeroInc/excrypto/x/crypto@errors.New("crypto@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@fmt.Errorf("github.com/runZeroInc/excrypto/x/crypto@fmt.Errorf("crypto@g' {} \;
find ${DIR}/ -type f -exec sed -i '' -e 's@fmt.Sprintf("github.com/runZeroInc/excrypto/x/crypto@fmt.Sprintf("crypto@g' {} \;
find ${DIR}/ -type f -name '*.go' -exec gofmt -w {} \;
find ${DIR}/ -type f -name '*.go' -exec gci write --skip-generated -s standard -s default -s 'prefix(github.com/runZeroInc)' --custom-order {} \;