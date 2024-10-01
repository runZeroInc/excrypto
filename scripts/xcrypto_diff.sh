#!/bin/bash
set -x

BASEDIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )
export LC_ALL=C

OREF=$(cat refs/xcrypto.hash)
if [[ "${OREF}" == "" ]]; then 
    OREF=master
fi

rm -rf x/crypto.upstream/ && \
git clone https://github.com/golang/crypto.git x/crypto.upstream/ || exit 1

(cd x/crypto.upstream; git checkout ${OREF}) || exit 1
./scripts/xcrypto_rewrite.sh ./x/crypto.upstream

diff --exclude=.git -ruN  x/crypto.upstream/ x/crypto/ > xcrypto.diff

rm -rf x/crypto.upstream/ && \
git clone https://github.com/golang/crypto.git x/crypto.upstream/ || exit 1
NREF=$(cd x/crypto.upstream/; git rev-parse HEAD)
./scripts/xcrypto_rewrite.sh ./x/crypto.upstream

rm -rf x/crypto/
mv x/crypto.upstream x/crypto
patch -p0 < xcrypto.diff
# echo $NREF > refs/xcrypto.hash