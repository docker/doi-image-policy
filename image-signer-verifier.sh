isv_image="docker/image-signer-verifier:0.5.2@sha256:e2d21db28bc9e982bfc3c2ac89c94b871f73711544573a43f55f3b74a56384a6"
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
