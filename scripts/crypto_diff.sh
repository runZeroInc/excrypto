#!/bin/bash
set -x

BASEDIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )
export LC_ALL=en_US.UTF-8

OREF=$(cat refs/crypto.hash)
if [[ "${OREF}" == "" ]]; then 
    OREF=master
fi

rm -rf crypto.upstream/ && \
git clone https://github.com/golang/go.git crypto.upstream/ || exit 1
( cd crypto.upstream; git checkout -- ; git reset --hard )

(cd crypto.upstream; git checkout ${OREF}) || exit 1
./scripts/xcrypto_rewrite.sh ./crypto.upstream/src/crypto/
rm -rf ./crypto.upstream/src/crypto/rand

rm -rf ./crypto.upstream/src/crypto/tls/fipsonly/

rm -rf ./crypto.upstream/src/crypto/boring
rm -rf ./crypto.upstream/src/crypto/internal/boring
cp -a ./crypto/boring ./crypto.upstream/src/crypto/boring
cp -a ./crypto/internal/boring ./crypto.upstream/src/crypto/internal/boring

rm -rf ./crypto.upstream/src/crypto/x509/internal/macos
rm -rf ./crypto.upstream/src/crypto/x509/root_*.go

rm -rf ./crypto.upstream/src/crypto/tls/link_test.go
rm -rf ./crypto.upstream/src/crypto/purego_test.go



diff --exclude=.git -ruN  crypto.upstream/src/crypto/ crypto/ > crypto.diff

(cd crypto.upstream && git checkout -- && git reset --hard && git checkout master) || exit 1
NREF=$(cd crypto.upstream/; git rev-parse HEAD)
./scripts/xcrypto_rewrite.sh ./crypto.upstream/src/crypto
rm -rf ./crypto.upstream/src/crypto/rand

rm -rf ./crypto.upstream/src/crypto/tls/fipsonly/

rm -rf ./crypto.upstream/src/crypto/boring
rm -rf ./crypto.upstream/src/crypto/internal/boring
cp -a ./crypto/boring ./crypto.upstream/src/crypto/boring
cp -a ./crypto/internal/boring ./crypto.upstream/src/crypto/internal/boring

rm -rf ./crypto.upstream/src/crypto/x509/internal/macos
rm -rf ./crypto.upstream/src/crypto/x509/root_*.go

rm -rf ./crypto.upstream/src/crypto/tls/link_test.go
rm -rf ./crypto.upstream/src/crypto/purego_test.go

rm -rf crypto/
cp -a crypto.upstream/src/crypto crypto
patch -p0 < crypto.diff
echo $NREF > refs/crypto.hash