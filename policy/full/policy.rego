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
	# TODO: attest.fetch should take the media type as it doesn't actually check the predicate type
	result := attest.fetch("https://slsa.dev/provenance/v1")
	not result.error
	some att in result.value
}

provenance_statements contains statement if {
	some att in provenance_attestations
	result := verify_attestation(att)
	not result.error

	# adds the descriptor to the statement so that we can use it in the output
	statement := json.patch(result.value, [{"op": "add", "path": "/descriptor", "value": att.resourceDescriptor}])

	statement.predicateType == "https://slsa.dev/provenance/v1"
}

provenance_subjects contains subject if {
	some statement in provenance_statements
	some subject in statement.subject
}

meta_commit_from_predicate(predicate) := commit if {
	some dep in predicate.buildDefinition.resolvedDependencies
	dep.uri == "git+https://github.com/docker-library/meta@refs/heads/main"
	commit := dep.digest.gitCommit
}

# TODO: use an auth token from input.parameters
build_info_response(meta_commit) := http.send({
	"method": "GET",
	"url": sprintf("https://api.github.com/repos/docker-library/meta/contents/builds.json?ref=%v", [meta_commit]),
	"headers": {
		"accept": "application/vnd.github.raw+json",
		"authorization": sprintf("token %s", [input.parameters.github_token]),
	},
	"force_json_decode": true,
	"cache": true,
})

submodule_info_response(meta_commit) := http.send({
	"method": "GET",
	"url": sprintf("https://api.github.com/repos/docker-library/meta/contents/.doi?ref=%v", [meta_commit]),
	"headers": {"authorization": sprintf("token %s", [input.parameters.github_token])},
	"cache": true,
})

definition_file_response_response(name, doi_commit) := http.send({
	"method": "GET",
	"url": sprintf("https://api.github.com/repos/docker-library/official-images/contents/library/%v?ref=%v", [name, doi_commit]),
	"headers": {
		"accept": "application/vnd.github.raw+json",
		"authorization": sprintf("token %s", [input.parameters.github_token]),
	},
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
	expected := "https://actions.github.io/buildtypes/workflow/v1"
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
		"attestation": statement,
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
		"attestation": statement,
		"details": {"predicate_type": statement.predicateType},
	}
}

provenance_statement_violations[statement_id] contains v if {
	some statement in provenance_statements
	statement_id := id(statement)

	build := build_info(statement)
	definition := build_definition(statement)

	# TODO: we should instead check that there are valid definition entries for *all* tags in the subjects
	relevant_definition_entries := {e | some e in definition.Entries; definition_entry_for_tags(e, input.tag)}

	# TODO: can there ever be more than one matching entry after the above check?
	# i.e., can there be multiple entries with the same tag?

	# the idea here is to perform the quick checks first and then the expensive checks
	# so that we can bail out fast if the entry matches
	# TODO: make sure that this is actually what happens
	every definition_entry in relevant_definition_entries {
		not matching_entry(definition_entry, build.source.entry, build.build.arch)
		not matching_git_checksum(definition_entry, build.source.reproducibleGitChecksum, build.build.arch)
	}

	v := {
		"type": "no_matching_entry",
		"description": "No matching entry in the build definition for this build",
		"attestation": statement,
		"details": {
			"predicate_type": statement.predicateType,
			"expected_entry": build.source.entry,
			"expected_tag": input.tag,
			"actual_entries": definition.Entries,
		},
	}
}

definition_entry_for_tags(definition_entry, tag) if {
	tag in definition_entry.Tags
}

matching_entry(definition_entry, build_source_entry, build_arch) if {
	every key in ["GitCommit", "GitRepo", "Builder", "Directory", "File"] {
		matching_value(key, definition_entry, build_source_entry, build_arch)
	}
}

matching_value(key, definition_entry, build_source_entry, build_arch) if {
	value_in_definition := definition_entry_value(definition_entry, key, build_arch)
	value_in_build_source := build_source_entry[key]
	value_in_definition != value_in_build_source
}

# use the architecture-specific value inside ArchValues if it exists, otherwise use the generic value
definition_entry_value(definition_entry, key, arch) := value if {
	def_key := ["ArchValues", sprintf("%s-%s", [arch, key])]
	value := object.get(definition_entry, def_key, object.get(definition_entry, key, null))
	value != null
}

matching_git_checksum(definition_entry, reproducible_git_checksum, build_arch) if {
	repo := definition_entry_value(definition_entry, "GitRepo", build_arch)
	commit := definition_entry_value(definition_entry, "GitCommit", build_arch)
	dir := definition_entry_value(definition_entry, "Directory", build_arch)

	result := attest.internals.reproducible_git_checksum(repo, commit, dir)
	checksum := result.value
	reproducible_git_checksum == checksum
}

bad_provenance_statements contains statement if {
	some statement in provenance_statements
	statement_id := id(statement)
	provenance_statement_violations[statement_id]
}

good_provenance_statements := provenance_statements - bad_provenance_statements

good_provenance_attestation_descriptors contains desc if {
	some good_statement in good_provenance_statements
	desc := good_statement.descriptor
}

global_violations contains v if {
	not input.parameters.github_token
	v := {
		"type": "missing_parameter",
		"description": "No github token found. Specify a valid GitHub token in the github_token input parameter",
		"attestation": null,
		"details": {},
	}
}

global_violations contains v if {
	count(provenance_attestations) == 0
	v := {
		"type": "missing_attestation",
		"description": "No https://slsa.dev/provenance/v1 attestation found",
		"attestation": null,
		"details": {},
	}
}

all_violations contains v if {
	some v in global_violations
}

all_violations contains v if {
	some violations in provenance_statement_violations
	some v in violations
}

result := {
	"success": allow,
	"violations": all_violations,
	"summary": {
		"subjects": provenance_subjects,
		"input_attestations": good_provenance_attestation_descriptors,
		"slsa_levels": ["SLSA_BUILD_LEVEL_3"],
		"verifier": "docker-official-images",
		"policy_uri": "https://docker.com/official/policy/v0.1",
	},
}

default allow := false

allow if {
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
