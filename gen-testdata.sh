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

function build_unsigned_image () {
    echo "Building $UNSIGNED_IMAGE_DIR..."
    docker buildx build "$TEST_IMAGE_DOCKERFILE_PATH" --sbom true --provenance true --platform linux/amd64,linux/arm64 \
      --output type=oci,tar=false,name="$TEST_IMAGE_REPO:$TEST_IMAGE_TAG",dest="$TESTDATA_PATH/$UNSIGNED_IMAGE_DIR"
}

function sign_image () {
    echo "Signing the image to generate $SIGNED_IMAGE_DIR..."
    ./image-signer-verifier.sh sign -i "oci:///$TESTDATA_PATH/$UNSIGNED_IMAGE_DIR" -o "oci:///$TESTDATA_PATH/$SIGNED_IMAGE_DIR" \
      --aws_arn "$AWS_KMS_ARN" --aws_region "$AWS_REGION"
}

function verify_image () {
    echo "Verifying the image to add VSA to $VERIFIED_IMAGE_DIR..."
    ./image-signer-verifier.sh verify -i "oci:///$TESTDATA_PATH/$SIGNED_IMAGE_DIR" \
      -o "oci:///$TESTDATA_PATH/$VERIFIED_IMAGE_DIR" --vsa --aws_arn "$AWS_KMS_ARN" \
      --aws_region "$AWS_REGION" --tuf-mock-path "/policy" --platform "linux/amd64" \
      --policy-id "docker-official-images"
}

# Check required commands
check_command aws
check_command docker
check_command jq
check_command yq
check_command openssl
check_command xxd

# Configuration
export AWS_PROFILE=${AWS_PROFILE:-"sandbox"}
export AWS_REGION=${AWS_REGION:-"us-east-1"}
AWS_KMS_ARN=${AWS_KMS_ARN:-"arn:aws:kms:us-east-1:175142243308:alias/doi-signing"}

TESTDATA_PATH="testdata"
TEST_IMAGE_DOCKERFILE_PATH="./test"
TEST_IMAGE_REPO="test-image"
TEST_IMAGE_TAG="test"
UNSIGNED_IMAGE_DIR="unsigned-test-image"
SIGNED_IMAGE_DIR="signed-test-image"
VERIFIED_IMAGE_DIR="verified-test-image"
NAME_ATTESTATION_FILENAME="name_attestation.json"
EXAMPLE_ATTESTATION_FILENAME="example_attestation.json"
ATTESTATION_PAYLOADTYPE="application/vnd.in-toto+json"

# Run steps
login_to_aws
cleanup_testdata
build_unsigned_image
sign_image
verify_image
echo "Process completed successfully."
