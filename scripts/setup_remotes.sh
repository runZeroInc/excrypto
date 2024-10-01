#!/bin/sh
BASEDIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )

git remote remove gosrc >/dev/null 2>&1
git remote add gosrc https://github.com/golang/go.git

git remote remove xcrypto  >/dev/null 2>&1
git remote add xcrypto https://github.com/golang/crypto.git

git remote -v