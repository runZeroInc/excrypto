#!/bin/bash
set -x

BASEDIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )
export LC_ALL=C
rm -rf x/crypto.upstream/ && \
git clone https://github.com/golang/crypto.git x/crypto.upstream/ || exit 1
find ./x/crypto.upstream/ -type f -exec sed -i '' -e 's@golang.org/x/crypto@github.com/runZeroInc/excrypto/x/crypto@g' {} \;
rm -f ./x/crypto.upstream/go.mod ./x/crypto.upstream/go.sum
rm -rf ./x/crypto.upstream/acme/
rm -rf x/crypto.upstream/.git
diff --exclude=.git -ruN x/crypto.upstream/ x/crypto/ > crypto.diff
rsync -arv --delete x/crypto.upstream/ x/crypto/;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto"@"github.com/runZeroInc/excrypto/crypto"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/subtle"@"github.com/runZeroInc/excrypto/crypto/subtle"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"encoding/asn1"@"github.com/runZeroInc/excrypto/encoding/asn1"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/cipher"@"github.com/runZeroInc/excrypto/crypto/cipher"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/dsa"@"github.com/runZeroInc/excrypto/crypto/dsa"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/rsa"@"github.com/runZeroInc/excrypto/crypto/rsa"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/x509@"github.com/runZeroInc/excrypto/crypto/x509@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/aes"@"github.com/runZeroInc/excrypto/crypto/aes"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/des"@"github.com/runZeroInc/excrypto/crypto/des"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/rc4"@"github.com/runZeroInc/excrypto/crypto/rc4"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/hmac"@"github.com/runZeroInc/excrypto/crypto/hmac"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/md5"@"github.com/runZeroInc/excrypto/crypto/md5"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/sha1"@"github.com/runZeroInc/excrypto/crypto/sha1"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/sha256"@"github.com/runZeroInc/excrypto/crypto/sha256"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/sha384"@"github.com/runZeroInc/excrypto/crypto/sha384"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/sha512"@"github.com/runZeroInc/excrypto/crypto/sha512"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/ecdsa"@"github.com/runZeroInc/excrypto/crypto/ecdsa"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/elliptic"@"github.com/runZeroInc/excrypto/crypto/elliptic"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@"crypto/ed25519"@"github.com/runZeroInc/excrypto/crypto/ed25519"@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@return "github.com/runZeroInc/excrypto/x/crypto@"x/crypto@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@errors.New("github.com/runZeroInc/excrypto/x/crypto@errors.New("x/crypto@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@fmt.Errorf("github.com/runZeroInc/excrypto/x/crypto@fmt.Errorf("x/crypto@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@fmt.Sprintf("github.com/runZeroInc/excrypto/x/crypto@fmt.Sprintf("x/crypto@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@return "github.com/runZeroInc/excrypto/x/crypto@"crypto@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@errors.New("github.com/runZeroInc/excrypto/x/crypto@errors.New("crypto@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@fmt.Errorf("github.com/runZeroInc/excrypto/x/crypto@fmt.Errorf("crypto@g' {} \;
find ./x/crypto/ -type f -exec sed -i '' -e 's@fmt.Sprintf("github.com/runZeroInc/excrypto/x/crypto@fmt.Sprintf("crypto@g' {} \;
find ./x/crypto/ -type f -name '*.go' -exec gofmt -w {} \;
find ./x/crypto/ -type f -name '*.go' -exec gci write --skip-generated -s standard -s default -s 'prefix(github.com/runZeroInc)' --custom-order {} \;
rm -rf x/crypto.upstream/