package attest

import rego.v1

split_digest := split(input.digest, ":")

digest_type := split_digest[0]

digest := split_digest[1]

keys := [
	{
		"id": "a0c296026645799b2a297913878e81b0aefff2a0c301e97232f717e14402f3e4",
		"key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgH23D1i2+ZIOtVjmfB7iFvX8AhVN\n9CPJ4ie9axw+WRHozGnRy99U2dRge3zueBBg2MweF0zrToXGig2v3YOrdw==\n-----END PUBLIC KEY-----",
		"from": "2023-12-15T14:00:00Z",
		"to": null,
		"status": "active",
		"signing-format": "dssev1",
	},
	{
		"id": "b281835e00059de24fb06bd6db06eb0e4a33d7bd7210d7027c209f14b19e812a",
		"key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgE4Jz6FrLc3lp/YRlbuwOjK4n6ac\njVkSDAmFhi3Ir2Jy+cKeEB7iRPcLvBy9qoMZ9E93m1NdWY6KtDo+Qi52Rg==\n-----END PUBLIC KEY-----",
		"from": "2023-12-15T14:00:00Z",
		"to": null,
		"status": "active",
		"signing-format": "dssev1",
	},
]

verify_opts := {"keys": keys}

verify_attestation(att) := attest.verify(att, verify_opts)

provenance_attestations contains att if {
	# TODO: this should take the media type as it doesn't actually check the predicate type
	result := attest.fetch("https://slsa.dev/provenance/v0.2")
	not result.error
	some att in result.value
}

provenance_signed_statements contains statement if {
	some att in provenance_attestations
	result := verify_attestation(att)
	not result.error
	statement := result.value
}

provenance_subjects contains subject if {
	some statement in provenance_signed_statements
	some subject in statement.subject
}

# we need to key this by statement_id rather than statement because we can't
# use an object as a key due to a bug(?) in OPA: https://github.com/open-policy-agent/opa/issues/6736
provenance_statement_violations[statement_id] contains v if {
	some att in provenance_attestations
	result := verify_attestation(att)
	err := result.error
	statement := unsafe_statement_from_attestation(att)
	statement_id := id(statement)
	v := {
		"type": "unsigned_statement",
		"description": sprintf("Statement is not correctly signed: %v", [err]),
		"attestation": statement,
		"details": {"error": err},
	}
}

provenance_statement_violations[statement_id] contains v if {
	some statement in provenance_signed_statements
	statement_id := id(statement)
	statement.predicateType != "https://slsa.dev/provenance/v0.2"
	v := is_not_violation(statement, "predicateType", "https://slsa.dev/provenance/v0.2", statement.predicateType, "wrong_predicate_type")
}

provenance_statement_violations[statement_id] contains v if {
	some statement in provenance_signed_statements
	statement_id := id(statement)
	v := field_value_does_not_equal(statement, "buildType", "https://mobyproject.org/buildkit@v1", "wrong_build_type")
}

provenance_statement_violations[statement_id] contains v if {
	some statement in provenance_signed_statements
	statement_id := id(statement)
	v := field_value_does_not_equal(statement, "metadata.completeness.materials", true, "incomplete_materials")
}

bad_provenance_statements contains statement if {
	some statement in provenance_signed_statements
	statement_id := id(statement)
	provenance_statement_violations[statement_id]
}

good_provenance_statements := provenance_signed_statements - bad_provenance_statements

sbom_attestations contains att if {
	result := attest.fetch("https://spdx.dev/Document")
	not result.error
	some att in result.value
}

sbom_signed_statements contains statement if {
	some att in sbom_attestations
	result := verify_attestation(att)
	not result.error
	statement := result.value
}

sbom_subjects contains subject if {
	some statement in sbom_signed_statements
	some subject in statement.subject
}

# we need to key this by statement_id rather than statement because we can't
# use an object as a key due to a bug(?) in OPA: https://github.com/open-policy-agent/opa/issues/6736
sbom_statement_violations[statement_id] contains v if {
	some att in sbom_attestations
	result := verify_attestation(att)
	err := result.error
	statement := unsafe_statement_from_attestation(att)
	statement_id := id(statement)
	v := {
		"type": "unsigned_statement",
		"description": sprintf("Statement is not correctly signed: %v", [err]),
		"attestation": statement,
		"details": {"error": err},
	}
}

sbom_statement_violations[statement_id] contains v if {
	some statement in sbom_signed_statements
	statement_id := id(statement)
	statement.predicate_type != "https://spdx.dev/Document"
	v := is_not_violation(statement, "predicateType", "https://spdx.dev/Document", statement.predicate_type, "wrong_predicate_type")
}

sbom_statement_violations[statement_id] contains v if {
	some statement in sbom_signed_statements
	statement_id := id(statement)
	v := field_value_does_not_equal(statement, "SPDXID", "SPDXRef-DOCUMENT", "wrong_spdx_id")
}

bad_sbom_statements contains statement if {
	some statement in sbom_signed_statements
	statement_id := id(statement)
	sbom_statement_violations[statement_id]
}

good_sbom_statements := sbom_signed_statements - bad_sbom_statements

global_violations contains v if {
	count(sbom_attestations) == 0
	v := {
		"type": "missing_attestation",
		"description": "No https://slsa.dev/provenance/v0.2 attestation found",
		"attestation": null,
		"details": {},
	}
}

global_violations contains v if {
	count(provenance_attestations) == 0
	v := {
		"type": "missing_attestation",
		"description": "No https://spdx.dev/Document attestation found",
		"attestation": null,
		"details": {},
	}
}

all_violations contains v if {
	some v in global_violations
}

all_violations contains v if {
	some violations in sbom_statement_violations
	some v in violations
}

all_violations contains v if {
	some violations in provenance_statement_violations
	some v in violations
}

subjects := union({sbom_subjects, provenance_subjects})

result := {
	"success": allow,
	"violations": all_violations,
	"summary": {
		"subjects": subjects,
		"slsa_levels": ["SLSA_BUILD_LEVEL_3"],
		"verifier": "docker-official-images",
		"policy_uri": "https://docker.com/official/policy/v0.1",
	},
}

default allow := false

allow if {
	count(good_sbom_statements) > 0
	count(good_provenance_statements) > 0
}

id(statement) := crypto.sha256(json.marshal(statement))

field_value_does_not_equal(statement, field, expected, type) := v if {
	path := split(field, ".")
	actual := object.get(statement.predicate, path, null)
	expected != actual
	v := is_not_violation(statement, field, expected, actual, type)
}

array_field_does_not_contain(statement, field, expected, type) := v if {
	path := split(field, ".")
	actual := object.get(statement.predicate, path, null)
	not expected in actual
	v := not_contains_violation(statement, field, expected, actual, type)
}

is_not_violation(statement, field, expected, actual, type) := {
	"type": type,
	"description": sprintf("%v is not %v", [field, expected]),
	"attestation": statement,
	"details": {
		"field": field,
		"actual": actual,
		"expected": expected,
	},
}

not_contains_violation(statement, field, expected, actual, type) := {
	"type": type,
	"description": sprintf("%v does not contain %v", [field, expected]),
	"attestation": statement,
	"details": {
		"field": field,
		"actual": actual,
		"expected": expected,
	},
}

# This is unsafe because we're not checking the signature on the attestation,
# do not call this unless you've already verified the attestation or you need the
# statement for some other reason
unsafe_statement_from_attestation(att) := statement if {
	payload := att.payload
	statement := json.unmarshal(base64.decode(payload))
}
