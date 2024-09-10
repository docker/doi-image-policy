isv_image="docker/image-signer-verifier:0.5.20@sha256:c3017e07df0b5c0f7f50c0f73fef866ce673a780c59c201f1b564f83b5d5fb93"
#isv_image="isv:latest"

mkdir -p $HOME/.local/tmp/sigstore

docker run \
  --rm \
  -e AWS_PROFILE \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_REGION \
  -e AWS_CONFIG_FILE=/.aws/config \
  -v $HOME/.local/tmp:/tmp \
  -v $HOME/.local/tmp/sigstore:/.sigstore \
  -v $HOME/.aws:/.aws:ro \
  -v $PWD/policy:/policy \
  -u $(id -u):$(id -g) \
  --network host \
  $isv_image \
  "$@"
