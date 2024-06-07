isv_image="docker/image-signer-verifier:0.5.1@sha256:e166570526e36095277799efcad1eba60306197ae8d94fd7ae465069842a52fe"
#isv_image="isv:latest"
docker run \
  --rm \
  -e AWS_PROFILE \
  -e AWS_REGION \
  -e AWS_CONFIG_FILE=/.aws/config \
  -v $HOME/.local/tmp:/tmp \
  -v $HOME/.local/tmp/sigstore:/.sigstore \
  -v $HOME/.aws:/.aws:ro \
  -v $HOME/.docker/:/.docker \
  -v $PWD/testdata:/testdata \
  -v $PWD/policy:/policy \
  -w /tmp \
  --network host \
  $isv_image \
  "$@"
