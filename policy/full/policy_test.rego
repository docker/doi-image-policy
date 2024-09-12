package attest

import rego.v1

config := {"keys": []}

purl := "pkg:docker/library/alpine:1.2.3"

statement := {"subject": [{"name": purl, "digest": {"sha256": "dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"}}]}

input_digest := "sha256:dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"

mock_verify_envelope({"name": "provenance_valid"}, k) := value_object({
	"type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"subject": [{
		"name": purl,
		"digest": {"sha256": "dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"},
	}],
	"predicate": {
		"buildType": "https://mobyproject.org/buildkit@v1",
		"metadata": {"completeness": {"materials": true}},
	},
})

mock_verify_envelope({"name": "provenance_wrong_predicate_type"}, k) := value_object({
	"type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://slsa.dev/provenance/v1",
	"subject": [{
		"name": purl,
		"digest": {"sha256": "dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"},
	}],
	"predicate": {
		"buildType": "https://mobyproject.org/buildkit@v1",
		"metadata": {"completeness": {"materials": true}},
	},
})

mock_verify_envelope({"name": "provenance_wrong_build_type"}, k) := value_object({
	"type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"subject": [{
		"name": purl,
		"digest": {"sha256": "dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"},
	}],
	"predicate": {
		"buildType": "some nonsense",
		"metadata": {"completeness": {"materials": true}},
	},
})

mock_verify_envelope({"name": "provenance_incomplete_materials"}, k) := value_object({
	"type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"subject": [{
		"name": purl,
		"digest": {"sha256": "dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"},
	}],
	"predicate": {
		"buildType": "https://mobyproject.org/buildkit@v1",
		"metadata": {"completeness": {"materials": false}},
	},
})

mock_verify_envelope({"name": "sbom_valid"}, k) := value_object({
	"type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://spdx.dev/Document",
	"subject": [{
		"name": purl,
		"digest": {"sha256": "dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"},
	}],
	"predicate": {"SPDXID": "SPDXRef-DOCUMENT"},
})

mock_verify_envelope({"name": "sbom_wrong_spdxid"}, k) := value_object({
	"type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://spdx.dev/Document",
	"subject": [{
		"name": purl,
		"digest": {"sha256": "dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"},
	}],
	"predicate": {"SPDXID": "not the one"},
})

mock_verify_envelope({"name": "unsigned", "payload": _}, _) := error_object("signature is not valid")

test_with_valid_provenance_and_sbom if {
	r := result with provenance_attestations as {{"name": "provenance_valid"}}
		with sbom_attestations as {{"name": "sbom_valid"}}
		with attest.verify as mock_verify_envelope
		with input.digest as input_digest
		with input.purl as purl
		with input.isCanonical as false

	r.success
	count(r.violations) == 0
}

test_with_provenance_with_wrong_predicate_type if {
	r := result with provenance_attestations as {{"name": "provenance_wrong_predicate_type"}}
		with sbom_attestations as {{"name": "sbom_valid"}}
		with attest.verify as mock_verify_envelope
		with input.digest as input_digest
		with input.purl as purl
		with input.isCanonical as false

	not r.success
	count(r.violations) == 1
	some v in r.violations
	print(yaml.marshal(v))
	v.type == "wrong_predicate_type"
	v.description == "predicateType is not https://slsa.dev/provenance/v0.2"
}

test_with_provenance_with_wrong_build_type if {
	r := result with provenance_attestations as {{"name": "provenance_wrong_build_type"}}
		with sbom_attestations as {{"name": "sbom_valid"}}
		with attest.verify as mock_verify_envelope
		with input.digest as input_digest
		with input.purl as purl
		with input.isCanonical as false

	not r.success
	count(r.violations) == 1
	some v in r.violations
	v.type == "wrong_build_type"
	v.description == "buildType is not https://mobyproject.org/buildkit@v1"
}

test_with_provenance_with_incomplete_materials if {
	r := result with provenance_attestations as {{"name": "provenance_incomplete_materials"}}
		with sbom_attestations as {{"name": "sbom_valid"}}
		with attest.verify as mock_verify_envelope
		with input.digest as input_digest
		with input.purl as purl
		with input.isCanonical as false

	not r.success
	count(r.violations) == 1
	some v in r.violations
	v.type == "incomplete_materials"
	v.description == "metadata.completeness.materials is not true"
}

test_with_sbom_with_wrong_spdxid if {
	r := result with provenance_attestations as {{"name": "provenance_valid"}}
		with sbom_attestations as {{"name": "sbom_wrong_spdxid"}}
		with attest.verify as mock_verify_envelope
		with input.digest as input_digest
		with input.purl as purl
		with input.isCanonical as false

	not r.success
	count(r.violations) == 1
	some v in r.violations
	v.type == "wrong_spdx_id"
	v.description == "SPDXID is not SPDXRef-DOCUMENT"
}

test_with_valid_and_invalid_statements if {
	r := result with provenance_attestations as {{"name": "provenance_valid"}, {"name": "provenance_incomplete_materials"}}
		with sbom_attestations as {{"name": "sbom_valid"}, {"name": "sbom_wrong_spdxid"}}
		with attest.verify as mock_verify_envelope
		with input.digest as input_digest
		with input.purl as purl
		with input.isCanonical as false

	r.success
	count(r.violations) == 2
}

test_with_multiple_invalid_statements if {
	r := result with provenance_attestations as {{"name": "provenance_wrong_build_type"}, {"name": "provenance_incomplete_materials"}}
		with sbom_attestations as {{"name": "sbom_wrong_spdxid"}}
		with attest.verify as mock_verify_envelope
		with input.digest as input_digest
		with input.purl as purl
		with input.isCanonical as false

	not r.success
	count(r.violations) == 3
}

test_with_no_attestations if {
	r := result with attest.fetch as value_object(set())
		with attest.verify as mock_verify_envelope
		with input.digest as input_digest
		with input.purl as purl
		with input.isCanonical as false

	not r.success
	count(r.violations) == 2

	some prov_v in r.violations
	prov_v.type == "missing_attestation"
	prov_v.description == "No https://slsa.dev/provenance/v0.2 attestation found"

	some sbom_v in r.violations
	sbom_v.type == "missing_attestation"
	sbom_v.description == "No https://spdx.dev/Document attestation found"
}

test_with_unsigned_attestation if {
	encoded_payload := base64.encode(json.marshal(statement))
	r := result with attest.fetch as value_object({{"name": "unsigned", "payload": encoded_payload}})
		with attest.verify as mock_verify_envelope
		with input.digest as input_digest
		with input.purl as purl
		with input.isCanonical as false

	not r.success
	count(r.violations) == 1
	some v in r.violations
	v.type == "unsigned_statement"
	v.description == "Statement is not correctly signed: signature is not valid"
	v.attestation == statement
}

layout_digest := "sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620"

outout_purl := "pkg:docker/test-image@test?platform=linux%2Famd64"

value_object(x) := {"value": x}

error_object(x) := {"error": x}
