#   Copyright Docker DOI Image Policy authors

#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

isv_image="docker/image-signer-verifier:0.6.11@sha256:1da7bf832736db04e9913dc191b1b7e539e1aa317cb2eba5ff277cdf6e26528a"
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
  -v $PWD/testdata:/testdata \
  -u $(id -u):$(id -g) \
  --network host \
  $isv_image \
  "$@"
