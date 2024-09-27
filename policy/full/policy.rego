package attest

import rego.v1

split_digest := split(input.digest, ":")

digest_type := split_digest[0]

digest := split_digest[1]

keys := [
	{
		"id": "a0c296026645799b2a297913878e81b0aefff2a0c301e97232f717e14402f3e4",
		"key": `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgH23D1i2+ZIOtVjmfB7iFvX8AhVN
9CPJ4ie9axw+WRHozGnRy99U2dRge3zueBBg2MweF0zrToXGig2v3YOrdw==
-----END PUBLIC KEY-----`,
		"from": "2023-12-15T14:00:00Z",
		"to": null,
		"status": "active",
		"signing-format": "dssev1",
	},
	{
		"id": "b281835e00059de24fb06bd6db06eb0e4a33d7bd7210d7027c209f14b19e812a",
		"key": `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgE4Jz6FrLc3lp/YRlbuwOjK4n6ac
jVkSDAmFhi3Ir2Jy+cKeEB7iRPcLvBy9qoMZ9E93m1NdWY6KtDo+Qi52Rg==
-----END PUBLIC KEY-----`,
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
	result := attest.fetch("https://slsa.dev/provenance/v1")
	not result.error
	some att in result.value
}

provenance_statements contains statement if {
	some att in provenance_attestations
	result := verify_attestation(att)
	not result.error
	statement := result.value
	statement.predicateType == "https://slsa.dev/provenance/v1"
}

provenance_subjects contains subject if {
	some statement in provenance_statements
	some subject in statement.subject
}

meta_commit_from_predicate(predicate) := commit if {
	# some dep in predicate.buildDefinition.resolvedDependencies

	# # TODO: this should be the actual meta repo
	# dep.uri == "git+https://github.com/docker/doi-signing-test@refs/heads/main"
	# commit := dep.digest.gitCommit

	# TODO: this doesn't work with doi-signing-test because the actual commit isn't in meta
	commit := "8c30112498668c1ae274b8596c2aff119fa76e7a"
}

build_info_response(meta_commit) := http.send({
	"method": "GET",
	"url": sprintf("https://api.github.com/repos/docker-library/meta/contents/builds.json?ref=%v", [meta_commit]),
	"headers": {"accept": "application/vnd.github.raw+json"},
	"force_json_decode": true,
	"cache": true,
})

submodule_info_response(meta_commit) := http.send({
	"method": "GET",
	"url": sprintf("https://api.github.com/repos/docker-library/meta/contents/.doi?ref=%v", [meta_commit]),
	"cache": true,
})

definition_file_response_response(name, doi_commit) := http.send({
	"method": "GET",
	"url": sprintf("https://api.github.com/repos/docker-library/official-images/contents/library/%v?ref=%v", [name, doi_commit]),
	"headers": {"accept": "application/vnd.github.raw+json"},
	"cache": true,
})

build_definition_file(name, doi_commit) := definition if {
	definition_file_response := definition_file_response_response(name, doi_commit)
	definition_file := definition_file_response.raw_body
	result := attest.internals.parse_library_definition(definition_file)
	not result.error
	definition := result.value
}

submodule_sha(meta_commit) := sha if {
	response := submodule_info_response(meta_commit)
	submodule_info := response.body
	submodule_info.type == "submodule"
	submodule_info.submodule_git_url == "https://github.com/docker-library/official-images.git"
	sha := response.body.sha
}

build_info(statement) := build if {
	build_id := statement.predicate.buildDefinition.externalParameters.inputs.buildId
	meta_commit := meta_commit_from_predicate(statement.predicate)
	response := build_info_response(meta_commit)
	response.status_code == 200
	builds_json := response.body
	build := builds_json[build_id]
}

build_definition(statement) := definition if {
	meta_commit := meta_commit_from_predicate(statement.predicate)
	doi_commit := submodule_sha(meta_commit)
	definition := build_definition_file(input.familiar_name, doi_commit)
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
	some statement in provenance_statements
	statement_id := id(statement)
	predicate := statement.predicate
	expected := "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
	predicate.buildDefinition.buildType != expected
	v := is_not_violation(statement, "buildDefinition.buildType", expected, predicate.buildDefinition.buildType, "wrong_build_type")
}

provenance_statement_violations[statement_id] contains v if {
	some statement in provenance_statements
	statement_id := id(statement)
	not build_info(statement)

	v := {
		"type": "build_info_request_failed",
		"description": "Error fetching build info for this statement",
		# "attestation": statement,
		"details": {"predicate_type": statement.predicateType},
	}
}

provenance_statement_violations[statement_id] contains v if {
	some statement in provenance_statements
	statement_id := id(statement)
	not build_definition(statement)

	v := {
		"type": "build_definition_request_failed",
		"description": "Error fetching build definition for this statement",
		# "attestation": statement,
		"details": {"predicate_type": statement.predicateType},
	}
}

provenance_statement_violations[statement_id] contains v if {
	some statement in provenance_statements
	statement_id := id(statement)

	build := build_info(statement)
	definition := build_definition(statement)

	every entry in definition.Entries {
		not valid_entry(entry, build)
	}

	v := {
		"type": "no_matching_entry",
		"description": "No matching entry in the build definition for this build",
		# "attestation": statement,
		"details": {
			"predicate_type": statement.predicateType,
			"expected_entry": build.source.entry,
			"expected_tag": input.tag,
			"actual_entries": definition.Entries,
		},
	}
}

valid_entry(entry, build) if {
	# TODO: should this instead check that *all* tags in the entry match *all* tags in the subjects?
	input.tag in entry.Tags
	entry.GitCommit == build.source.entry.GitCommit
	entry.GitRepo == build.source.entry.GitRepo
	entry.Builder == build.source.entry.Builder
	entry.Directory == build.source.entry.Directory
	entry.File == build.source.entry.File
}

bad_provenance_statements contains statement if {
	some statement in provenance_statements
	statement_id := id(statement)
	provenance_statement_violations[statement_id]
}

good_provenance_statements := provenance_statements - bad_provenance_statements

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
	# "attestation": statement,
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
