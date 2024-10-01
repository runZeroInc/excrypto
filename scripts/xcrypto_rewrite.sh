#!/bin/bash

DIR=$1

if [[ "${DIR}" == "" ]]; then
    echo "missing directory argument"
    exit 1
fi

rm -f ${DIR}/go.mod ${DIR}/go.sum

OPTS="-prune -o -name '.git'"

find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@go 1\.24@go 1.23@g' {} \;

find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@"crypto/internal@"github.com/runZeroInc/excrypto/crypto/internal@g' {} \;
find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@"internal@"github.com/runZeroInc/excrypto/crypto/internal@g' {} \;

find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@"encoding/asn1"@"github.com/runZeroInc/excrypto/encoding/asn1"@g' {} \;

find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@"golang.org/x/crypto@"github.com/runZeroInc/excrypto/x/crypto@g' {} \;

find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@"crypto@"github.com/runZeroInc/excrypto/crypto@g' {} \;

find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@return "github.com/runZeroInc/excrypto/x/crypto@"x/crypto@g' {} \;
find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@errors.New("github.com/runZeroInc/excrypto/x/crypto@errors.New("x/crypto@g' {} \;
find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@fmt.Errorf("github.com/runZeroInc/excrypto/x/crypto@fmt.Errorf("x/crypto@g' {} \;
find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@fmt.Sprintf("github.com/runZeroInc/excrypto/x/crypto@fmt.Sprintf("x/crypto@g' {} \;

find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@return "github.com/runZeroInc/excrypto/crypto@"crypto@g' {} \;
find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@errors.New("github.com/runZeroInc/excrypto/crypto@errors.New("crypto@g' {} \;
find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@fmt.Errorf("github.com/runZeroInc/excrypto/crypto@fmt.Errorf("crypto@g' {} \;
find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@fmt.Sprintf("github.com/runZeroInc/excrypto/crypto@fmt.Sprintf("crypto@g' {} \;

find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@github.com/runZeroInc/excrypto/crypto/rand@crypto/rand@g' {} \;

find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@p256SubInternal@p256SubInternalExCrypto@g' {} \;
find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@p256MulInternal@p256MulInternalExCrypto@g' {} \;
find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@p256SqrInternal@p256SqrInternalExCrypto@g' {} \;
find ${DIR}/ ${OPTS} -type f -exec sed -i '' -e 's@p256IsZero@p256IsZeroExCrypto@g' {} \;


find ${DIR}/ ${OPTS} -type f -name '*.go' -exec gofmt -w {} \;
find ${DIR}/ ${OPTS} -type f -name '*.go' -exec gci write --skip-generated -s standard -s default -s 'prefix(github.com/runZeroInc)' --custom-order {} \;