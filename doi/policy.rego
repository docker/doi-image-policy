package docker

import rego.v1

import data.config

splitDigest := split(input.digest, ":")

digestType := splitDigest[0]

digest := splitDigest[1]

pred := "https://docker.io/attestation/name/v0.1"

allow if {
	print("### Starting policy evaluation ###")
	some env in attestations.attestation(pred)
	print("found name attestation")
	some statement in verified_statements(config.doi.keys, env)
	# check predicateType just in case
	statement.predicateType == pred
	print("### Policy Evaluation Complete ###")
}


verified_statements(keys, env) := statements if {
	statements := {statement |
		print("verifying envelope...")
		statement := attestations.verify_envelope(env, keys)
		print("verified envelope signature")
		some subject in statement.subject
		print("found subject in statement")
		valid_subject(subject)
	}
}


valid_subject(sub) if {
	print("valid_subject")
	print("sub.digest[digestType]:", sub.digest[digestType])
	print("digest", digest)
	sub.digest[digestType] == digest
	print("digest matches")
	valid_subject_name(sub.name)
}

valid_subject_name(name) if {
	input.canonical
	print("is canonical, ignoring name")
}

valid_subject_name(name) if {
	not input.canonical
	print("valid_subject_name...")
	print("name:", name)
	print("input.purl:", input.purl)
	name == input.purl
	print("name match")
}
