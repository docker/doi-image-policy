#!/bin/bash
./image-signer-verifier.sh test -i oci:///testdata/verified-test-image -d policy/doi-vsa "$@"
