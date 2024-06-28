#!/bin/bash
set -eo pipefail

echo "Starting the process to generate testdata for the signing package..."

# Define functions
function check_command () {
    command -v "$1" >/dev/null 2>&1 || { echo >&2 "This script requires $1 but it's not installed.  Aborting."; exit 1; }
}

function login_to_aws () {
    if ! aws sts get-caller-identity > /dev/null 2>&1; then
        echo "SSO session has expired or is not valid. Logging in using AWS SSO."
        aws sso login
    else
        echo "SSO session is still valid."
    fi
}

function cleanup_testdata () {
    echo "Cleaning up existing testdata..."
    rm -rf "${TESTDATA_PATH:?}/${UNSIGNED_IMAGE_DIR:?}"
    rm -rf "${TESTDATA_PATH:?}/${SIGNED_IMAGE_DIR:?}"
    rm -rf "${TESTDATA_PATH:?}/${VERIFIED_IMAGE_DIR:?}"
}

function sign_image () {
    echo "Signing the image to generate $SIGNED_IMAGE_DIR..."
    ./image-signer-verifier.sh sign -i "docker://$TEST_IMAGE_REPO:$TEST_IMAGE_TAG" -o "oci://$TESTDATA_PATH/$SIGNED_IMAGE_DIR" \
      --kms-key-ref "$AWS_KMS_ARN" --kms-region "$AWS_REGION" --attach --referrers=false
}

function verify_image () {
    echo "Verifying the image to add VSA to $VERIFIED_IMAGE_DIR..."
    ./image-signer-verifier.sh verify -i "oci://$TESTDATA_PATH/$SIGNED_IMAGE_DIR" \
      -o "oci://$TESTDATA_PATH/$VERIFIED_IMAGE_DIR" --attestation-style "attached" \
      --vsa --kms-key-ref "$AWS_KMS_ARN" --attach --referrers=false \
      --kms-region "$AWS_REGION" --tuf-mock-path "$POLICY_PATH" --platform "linux/amd64" \
      --policy-id "$POLICY_ID"
}

function verify_image_vsa () {
    echo "Verifying the VSA on $VERIFIED_IMAGE_DIR..."
    ./image-signer-verifier.sh verify -i "oci://$TESTDATA_PATH/$VERIFIED_IMAGE_DIR" \
      --attestation-style "attached" \
      --tuf-mock-path "$POLICY_PATH" --platform "linux/amd64" \
      --policy-id "$VSA_POLICY_ID"
}

# Check required commands
check_command aws
check_command docker

# Configuration
export AWS_PROFILE=${AWS_PROFILE:-"sandbox"}
export AWS_REGION=${AWS_REGION:-"us-east-1"}
AWS_KMS_ARN=${AWS_KMS_ARN:-"arn:aws:kms:us-east-1:175142243308:alias/doi-signing"}

TESTDATA_PATH="testdata"
TEST_IMAGE_REPO="nginx"
TEST_IMAGE_TAG="1.27.0-alpine-slim"
UNSIGNED_IMAGE_DIR="unsigned-test-image"
SIGNED_IMAGE_DIR="signed-test-image"
VERIFIED_IMAGE_DIR="verified-test-image"
POLICY_PATH="policy"
POLICY_ID="docker-official-images"
VSA_POLICY_ID="docker-official-images-vsa"

# Run steps
login_to_aws
cleanup_testdata
sign_image
verify_image
verify_image_vsa
echo "Process completed successfully."
