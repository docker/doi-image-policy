#!/bin/bash
set -eo pipefail

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

function start_registry () {
    echo "Starting the registry..."
    docker run --rm -d -p 5000:5000 --name registry registry:2
}

function stop_registry () {
    echo "Stopping the registry..."
    docker stop registry
}

function sign_image () {
    echo "Signing the attestations on $INPUT_IMAGE and storing in $REFERRERS_REPO..."
    ./image-signer-verifier.sh sign -i "$INPUT_IMAGE" \
      --referrers-dest "$REFERRERS_REPO" \
      --kms-key-ref "$AWS_KMS_ARN" --kms-region "$AWS_REGION"
}

function verify_image () {
    echo "Verifying the attestations for $INPUT_IMAGE and storing a VSA in $REFERRERS_REPO..."
    ./image-signer-verifier.sh verify -i "$INPUT_IMAGE" \
      --referrers-dest "$REFERRERS_REPO" \
      --referrers-source "$REFERRERS_REPO" \
      --vsa --kms-key-ref "$AWS_KMS_ARN" \
      --kms-region "$AWS_REGION" --tuf-mock-path "$POLICY_PATH" --platform "linux/amd64" \
      --policy-id "$POLICY_ID"
}

function verify_image_vsa () {
    echo "Verifying the VSA for $INPUT_IMAGE..."
    ./image-signer-verifier.sh verify -i "$INPUT_IMAGE" \
      --referrers-source "$REFERRERS_REPO" \
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

TEST_IMAGE_REPO="nginx"
TEST_IMAGE_TAG="1.27.0-alpine-slim"
INPUT_IMAGE="docker://$TEST_IMAGE_REPO:$TEST_IMAGE_TAG"
REFERRERS_REPO="docker://localhost:5000/$TEST_IMAGE_REPO"
POLICY_PATH="policy"
POLICY_ID="docker-official-images"
VSA_POLICY_ID="docker-official-images-vsa"

# Run steps
login_to_aws

start_registry
trap stop_registry EXIT

sign_image
verify_image
verify_image_vsa

echo "Process completed successfully."
