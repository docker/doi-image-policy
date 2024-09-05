isv_image="docker/image-signer-verifier:0.5.17@sha256:bde1b7cdd36933b620353aa83f4115cc13e1d6230902c7a892b1580520607b55"
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
