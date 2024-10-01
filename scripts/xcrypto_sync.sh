#!/bin/sh
BASEDIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )
export LC_ALL=C
rm -rf x/crypto.upstream/ && \
git clone https://github.com/golang/crypto.git x/crypto.upstream/ && \
find ./x/crypto.upstream/ -type f -exec sed -i '' -e 's@golang.org/x/crypto@github.com/runZeroInc/excrypto/x/crypto@g' {} \; && \
#
# find ./x/crypto.upstream/ -type f -exec sed -i '' -e 's@"crypto"/"github.com/runZeroInc/excrypto/crypto"@g' {} \; && \
# find ./x/crypto.upstream/ -type f -exec sed -i '' -e 's@"crypto/subtle"/"github.com/runZeroInc/excrypto/crypto/subtle"@g' {} \; && \
# find ./x/crypto.upstream/ -type f -exec sed -i '' -e 's@"crypto/cipher"/"github.com/runZeroInc/excrypto/crypto/cipher"@g' {} \; && \
# find ./x/crypto.upstream/ -type f -exec sed -i '' -e 's@"crypto/dsa"/"github.com/runZeroInc/excrypto/crypto/dsa"@g' {} \; && \
# find ./x/crypto.upstream/ -type f -exec sed -i '' -e 's@"crypto/hmac"/"github.com/runZeroInc/excrypto/crypto/hmac"@g' {} \; && \
# find ./x/crypto.upstream/ -type f -exec sed -i '' -e 's@"crypto/md5"/"github.com/runZeroInc/excrypto/crypto/md5"@g' {} \; && \
# find ./x/crypto.upstream/ -type f -exec sed -i '' -e 's@"crypto/sha1"/"github.com/runZeroInc/excrypto/crypto/sha1"@g' {} \; && \
# find ./x/crypto.upstream/ -type f -exec sed -i '' -e 's@"crypto/sha256"/"github.com/runZeroInc/excrypto/crypto/sha256"@g' {} \; && \
# find ./x/crypto.upstream/ -type f -exec sed -i '' -e 's@"crypto/sha384"/"github.com/runZeroInc/excrypto/crypto/sha384"@g' {} \; && \
# find ./x/crypto.upstream/ -type f -exec sed -i '' -e 's@"crypto/sha512"/"github.com/runZeroInc/excrypto/crypto/sha512"@g' {} \; && \
rm -f ./x/crypto.upstream/go.mod ./x/crypto.upstream/go.sum && \
rm -rf ./x/crypto.upstream/acme/ && \
diff --exclude=.git -ruN x/crypto.upstream/ x/crypto/ > crypto.diff && \
rm -rf x/crypto.upstream/