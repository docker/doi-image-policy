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
    rm -f  "${TESTDATA_PATH:?}/${PUBLIC_KEY_FILENAME:?}"
}

function build_unsigned_image () {
    echo "Building $UNSIGNED_IMAGE_DIR..."
    docker buildx build "$TEST_IMAGE_DOCKERFILE_PATH" --sbom true --provenance true --platform linux/amd64,linux/arm64 \
      --output type=oci,tar=false,name="$TEST_IMAGE_REPO:$TEST_IMAGE_TAG",dest="$TESTDATA_PATH/$UNSIGNED_IMAGE_DIR"
}

function sign_image () {
    echo "Signing the image to generate $SIGNED_IMAGE_DIR..."
    ./image-signer-verifier.sh sign -i "oci://$TESTDATA_PATH/$UNSIGNED_IMAGE_DIR" -o "oci://$TESTDATA_PATH/$SIGNED_IMAGE_DIR" \
      --aws_arn "$AWS_KMS_ARN" --aws_region "$AWS_REGION" --vsa \
      --slsa-level 3 --slsa-policy-uri "https://docker.com/library/policy" \
      --slsa-verifier-id "https://docker.com"
}

function output_public_key () {
    echo "Outputting public key to $PUBLIC_KEY_FILENAME..."
    # Fetch the base64-encoded public key
    PUB_KEY=$(aws kms get-public-key --key-id "$AWS_KMS_ARN" --output text --query PublicKey --region "$AWS_REGION")

    # Format the public key in PEM format
    {
        echo "-----BEGIN PUBLIC KEY-----"
        echo "$PUB_KEY" | fold -w 64  # Ensure that lines are wrapped at 64 characters
        echo "-----END PUBLIC KEY-----"
    } > "$TESTDATA_PATH/$PUBLIC_KEY_FILENAME"
    local key=`cat "$TESTDATA_PATH/$PUBLIC_KEY_FILENAME"`
    local keyid=`openssl pkey -in "$TESTDATA_PATH/$PUBLIC_KEY_FILENAME" -pubin -outform DER | openssl dgst -sha256 -binary| xxd -p -c 256`
    echo "Public key fingerprint: $keyid"
    yq eval -i ".config.doi.keys[0].id = \"$keyid\"" doi/data.yaml
    yq eval -i ".config.doi.keys[0].key = \"$key\"" doi/data.yaml
    rm -f "$TESTDATA_PATH/$PUBLIC_KEY_FILENAME"
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
NAME_ATTESTATION_FILENAME="name_attestation.json"
EXAMPLE_ATTESTATION_FILENAME="example_attestation.json"
ATTESTATION_PAYLOADTYPE="application/vnd.in-toto+json"
PUBLIC_KEY_FILENAME="pubkey.pem"

# Run steps
login_to_aws
cleanup_testdata
build_unsigned_image
sign_image
output_public_key
echo "Process completed successfully."
