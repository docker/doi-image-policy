isv_image="docker/image-signer-verifier:0.4.4@sha256:9160604a2e3279a20d58aaa3f37d6511372de63701aa371598a9c479e5fd6f6b"
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
