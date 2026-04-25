#!/bin/bash
# Run sed in C locale to avoid "RE error: illegal byte sequence" on binary blobs.
export LC_ALL=C
export LANG=C

DIR=$1

if [[ "${DIR}" == "" ]]; then
    echo "missing directory argument"
    exit 1
fi

rm -f ${DIR}/go.mod ${DIR}/go.sum

# Build a sorted list of regular files, skipping any .git subdir entries.
FILES=$(find "${DIR}/" -name .git -prune -o -type f -print)
GOFILES=$(find "${DIR}/" -name .git -prune -o -type f -name '*.go' -print)

apply_sed() {
    local expr=$1
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        sed -i '' -e "$expr" "$f" 2>/dev/null || true
    done <<<"$FILES"
}

apply_sed 's@go 1\.24@go 1.23@g'

apply_sed 's@"crypto/internal@"github.com/runZeroInc/excrypto/crypto/internal@g'
apply_sed 's@"internal@"github.com/runZeroInc/excrypto/crypto/internal@g'

apply_sed 's@"encoding/asn1"@"github.com/runZeroInc/excrypto/encoding/asn1"@g'

apply_sed 's@"golang.org/x/crypto@"github.com/runZeroInc/excrypto/x/crypto@g'

apply_sed 's@"crypto@"github.com/runZeroInc/excrypto/crypto@g'

apply_sed 's@return "github.com/runZeroInc/excrypto/x/crypto@return "x/crypto@g'
apply_sed 's@errors.New("github.com/runZeroInc/excrypto/x/crypto@errors.New("x/crypto@g'
apply_sed 's@fmt.Errorf("github.com/runZeroInc/excrypto/x/crypto@fmt.Errorf("x/crypto@g'
apply_sed 's@fmt.Sprintf("github.com/runZeroInc/excrypto/x/crypto@fmt.Sprintf("x/crypto@g'
apply_sed 's@panic("github.com/runZeroInc/excrypto/x/crypto@panic("x/crypto@g'

apply_sed 's@return "github.com/runZeroInc/excrypto/crypto@return "crypto@g'
apply_sed 's@errors.New("github.com/runZeroInc/excrypto/crypto@errors.New("crypto@g'
apply_sed 's@fmt.Errorf("github.com/runZeroInc/excrypto/crypto@fmt.Errorf("crypto@g'
apply_sed 's@fmt.Sprintf("github.com/runZeroInc/excrypto/crypto@fmt.Sprintf("crypto@g'
apply_sed 's@panic("github.com/runZeroInc/excrypto/crypto@panic("crypto@g'

apply_sed 's@github.com/runZeroInc/excrypto/crypto/rand@crypto/rand@g'

apply_sed 's@p256SubInternal@p256SubInternalExCrypto@g'
apply_sed 's@p256MulInternal@p256MulInternalExCrypto@g'
apply_sed 's@p256SqrInternal@p256SqrInternalExCrypto@g'
apply_sed 's@p256IsZero@p256IsZeroExCrypto@g'

while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    gofmt -w "$f" >/dev/null 2>&1 || true
done <<<"$GOFILES"

while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    gci write --skip-generated -s standard -s default -s 'prefix(github.com/runZeroInc)' --custom-order "$f" >/dev/null 2>&1 || true
done <<<"$GOFILES"
