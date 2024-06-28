#!/bin/bash

fails=0

./image-signer-verifier.sh test -d policy/full "$@" || ((fails++))
./image-signer-verifier.sh test -d policy/vsa "$@" || ((fails++))

if [ $fails -gt 0 ]; then
    echo "Failed $fails tests"
    exit 1
fi
echo "All tests passed"
