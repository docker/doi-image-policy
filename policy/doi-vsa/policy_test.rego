package attest_test

import rego.v1

import data.attest

config := {"keys": []}

purl := "pkg:docker/library/alpine:1.2.3"

statement := {"subject": [{"name": purl, "digest": {"sha256": "dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"}}]}

input_digest := "sha256:dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"

mock_verify_envelope({"name": "valid"}, k) := {
	"type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://slsa.dev/verification_summary/v1",
	"subject": [{
		"name": purl,
		"digest": {"sha256": "dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"},
	}],
	"predicate": {
		"policy": {"uri": "https://docker.com/official/policy/v0.1"},
		"resourceUri": "pkg:docker/test-image@test?digest=sha256%3A7c43c2a4affcff17f3d756058e335fcde7249aa7014047251b5fe512b6bff213&platform=linux%2Famd64",
		"timeVerified": "2024-05-24T12:44:03Z",
		"verificationResult": "PASSED",
		"verifiedLevels": ["SLSA_BUILD_LEVEL_3"],
		"verifier": {"id": "docker-official-images"},
	},
}

mock_verify_envelope({"name": "invalid"}, k) := {
	"type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://slsa.dev/verification_summary/v1",
	"subject": [{
		"name": purl,
		"digest": {"sha256": "dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"},
	}],
	"predicate": {
		"policy": {"uri": "https://docker.com/official/policy/v0.1"},
		"resourceUri": "pkg:docker/test-image@test?digest=sha256%3A7c43c2a4affcff17f3d756058e335fcde7249aa7014047251b5fe512b6bff213&platform=linux%2Famd64",
		"timeVerified": "2024-05-24T12:44:03Z",
		"verificationResult": "FAILED",
		"verifiedLevels": [],
		"verifier": {"id": "docker-official-images"},
	},
}

mock_verify_envelope({"name": "invalid2"}, k) := {
	"type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://slsa.dev/verification_summary/v1",
	"subject": [{
		"name": purl,
		"digest": {"sha256": "dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"},
	}],
	"predicate": {
		"policy": {"uri": "https://docker.com/official/policy/v0.1"},
		"resourceUri": "pkg:docker/test-image@test?digest=sha256%3A7c43c2a4affcff17f3d756058e335fcde7249aa7014047251b5fe512b6bff213&platform=linux%2Famd64",
		"timeVerified": "2024-05-24T12:44:03Z",
		"verificationResult": "PASSED",
		"verifiedLevels": ["SLSA_BUILD_LEVEL_3"],
		"verifier": {"id": "wrong-verifier"},
	},
}

test_with_valid_statement if {
	r := attest.result with attestations.attestation as {{"name": "valid"}, {"name": "invalid"}}
		with attestations.verify_envelope as mock_verify_envelope
		with input.digest as input_digest
		with input.purl as purl
		with input.isCanonical as false

	r.success
	# count(r.violations) == 0
}

test_with_no_valid_statement if {
	r := attest.result with attestations.attestation as {{"name": "invalid"}, {"name": "invalid2"}}
		with attestations.verify_envelope as mock_verify_envelope
		with input.digest as input_digest
		with input.purl as purl
		with input.isCanonical as false

	not r.success
	# count(r.violations) > 0
}

test_with_no_attestations if {
	r := attest.result with attestations.attestation as set()
		with attestations.verify_envelope as mock_verify_envelope
		with input.digest as input_digest
		with input.purl as purl
		with input.isCanonical as false

	not r.success
}

layout_digest := "sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620"

outout_purl := "pkg:docker/test-image@test?platform=linux%2Famd64"
