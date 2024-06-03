package attest

import rego.v1

# TODO: this is a placeholder, it should do more validation of the statements

keys := [{
	"id": "a0c296026645799b2a297913878e81b0aefff2a0c301e97232f717e14402f3e4",
	"key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgH23D1i2+ZIOtVjmfB7iFvX8AhVN\n9CPJ4ie9axw+WRHozGnRy99U2dRge3zueBBg2MweF0zrToXGig2v3YOrdw==\n-----END PUBLIC KEY-----",
	"from": "2023-12-15T14:00:00Z",
	"to": null,
	# this key is still active
	"status": "active",
	"signing-format": "dssev1",
}]

atts := union({
	attestations.attestation("https://slsa.dev/provenance/v0.2"),
	attestations.attestation("https://spdx.dev/Document"),
})

statements contains s if {
	some att in atts
	s := attestations.verify_envelope(att, keys)
}

subjects contains subject if {
	some statement in statements
	some subject in statement.subject
}

result := {
	"success": true,
	"violations": set(),
	"summary": {
		"subjects": subjects,
		"slsa_levels": ["SLSA_BUILD_LEVEL_3"],
		"verifier": "docker-official-images",
		"policy_uri": "https://docker.com/official/policy/v0.1",
	},
}
