isv_image="docker/image-signer-verifier:0.4.5@sha256:4dec75173e68bf5952fcef54ac60621f3af26a7ccb057928559e5e5dc1326592"
#isv_image="isv:latest"
docker run \
  --rm \
  -e AWS_PROFILE \
  -e AWS_REGION \
  -e AWS_CONFIG_FILE=/.aws/config \
  -v $HOME/.local/tmp:/tmp \
  -v $HOME/.local/tmp:/.sigstore/ \
  -v $HOME/.aws:/.aws \
  -v $HOME/.docker/:/.docker \
  -v $PWD/testdata:/testdata \
  -v $PWD/doi:/doi \
  --network host \
  --user $(id -u):$(id -g) \
  $isv_image \
  $@
