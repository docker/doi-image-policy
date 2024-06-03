isv_image="docker/image-signer-verifier:local"
#isv_image="isv:latest"
docker run \
  --rm \
  -e AWS_PROFILE \
  -e AWS_REGION \
  -e AWS_CONFIG_FILE=/.aws/config \
  -v $HOME/.local/tmp:/tmp \
  -v $HOME/.local/tmp/sigstore:/.sigstore \
  -v $HOME/.aws:/.aws \
  -v $HOME/.docker/:/.docker \
  -v $PWD/testdata:/testdata \
  -v $PWD/policy:/policy \
  -w /tmp \
  --network host \
  --user $(id -u):$(id -g) \
  $isv_image \
  "$@"
