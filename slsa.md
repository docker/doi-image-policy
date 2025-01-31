# DOI GitHub Actions SLSA Builder Evaluation

This is a self-evaluation of the [SLSA v1.0](https://slsa.dev/spec/v1.0/) build level for Docker Official Images (DOI) GitHub Actions (GHA) Workflow trusted builder.

| Builder ID | `https://github.com/docker-library/meta/.github/workflows/build.yml@refs/heads/main` |
| ---------- | ------------------------------------------------------------------------------------ |

## Applicability

A subset of DOI builds run on the [meta](https://github.com/docker-library/meta) GHA [workflow](https://github.com/docker-library/meta/blob/HEAD/.github/workflows/build.yml).

Applicable builds are limited to the following image platforms:

- `linux/amd64`
- `linux/386`

The list of all applicable images can be found in [subset.txt](https://github.com/docker-library/meta/blob/HEAD/subset.txt).

## Build Level Assertion

The DOI build platform can be trusted to produce Build Level 3 artifacts on images that are built by the `meta` GHA workflow due to the strengthened unforgeability and isolation controls for provenance generation as detailed in the following sections.

## Build Model

DOI GHA workflow builder is modeled around the [GHA workflow build type](https://actions.github.io/buildtypes/workflow/v1).

The DOI build platform in its entirety extends beyond the GHA workflow, but we choose to limit the trusted boundary for this analysis to the DOI GHA workflow.
In this model, the GHA workflow itself is the trusted control plane and all other platform automation outside it are considered untrusted external parameters and dependencies that are "to be verified" according to a set of expectations that we define as the source of truth for DOI builds.

### Build Platform Components

Build platform components are defined according to the [SLSA v1.0 spec terminology](https://slsa.dev/spec/v1.0/verifying-systems#build-platform-components) below.

#### Control Plane

The control plane for the DOI GHA workflow builder is the [meta GHA workflow file](https://github.com/docker-library/meta/blob/HEAD/.github/workflows/build.yml).

This GHA workflow orchestrates each build stage and is operated by administrators that have privilege to modify the control plane.
The workflow is made available to the public for transparency and is version controlled in git with branch protection controls requiring two person review by maintainers of the DOI build platform.

##### Isolation

Provenance generation and signing is sufficiently isolated from the build environment through the use of separate GitHub-hosted runner VMs via [jobs](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/using-jobs-in-a-workflow).

##### Unforgeability

Access to signing operations is provided by [OIDC](https://openid.net/) authentication of the control plane (GHA workflow) to KMS managed keys that store key material in a Hardware Security Module (HSM).
Only trusted jobs in the GHA workflow are provided access to the ID Token to obtain tokens for KMS signing.
Specifically, the job that handles the build environment is NOT granted permission to request ID Tokens on behalf of the workflow.
This provides sufficient security controls to ensure unforgeable provenance generation.

Use of the KMS is audited and alerts are in place for unauthorized access by entities outside of the DOI GHA workflow identity.

#### Cache

Build artifacts are passed between jobs in the workflow using a combination of [workflow artifacts](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/storing-and-sharing-data-from-a-workflow) and [job outputs](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/passing-information-between-jobs).

Job outputs are treated as a trusted channel to distribute the cryptographic digest of artifacts so that each job can verify the integrity of build artifacts cached outside of the trusted builder boundary in workflow artifact storage.

#### External Parameters

In addition to what is defined by the [GHA build type](https://actions.github.io/buildtypes/workflow/v1), all workflow inputs are considered external parameters for this build model.

These inputs are verified according to a set of expectations about them for authentic DOI builds.
See [#verifying-expectations-for-doi-builds](#verifying-expectations-for-doi-builds).

#### Build Environment

The build environment is a `job` within the DOI GHA workflow that is named `build`.
The build job is isolated from the control plane and other jobs within the workflow with the use of GitHub-hosted runner virtual machines.

The build environment cannot influence provenance generation because provenance is generated by the control plane in a separate job.

Access to key material and signing operations is not permitted for the build environment through the use of [job permissions](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token#setting-the-github_token-permissions-for-a-specific-job).
The `build` job is not granted `id-token` permissions, therefore it cannot generate a workload identity token to authenticate with the signing KMS.

#### Resolved Dependencies

The minimum required resolved dependency for a DOI GHA workflow is the resolved git commit URI for the workflow run on the [meta](https://github.com/docker-library/meta) repository.

The [official-images](https://github.com/docker-library/official-images) and [meta-scripts](https://github.com/docker-library/meta-scripts) repositories are dependencies for DOI builds and are [git submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules) in the meta repository.
Therefore, the commit references for those repositories are obtained by the URI for the meta repository git commit.

#### Outputs

Artifacts are output from the build system as OCI images.
Images are stored in an OCI registry as build "outputs" that are later collected by a separate process that deploys them to the image architecture and library namespaces.

The provenance attestation generated by the trusted builder captures the cryptographic digest of the image as a subject of the predicate, such that if the image was modified after being output, the verification of the provenance attestation would fail.

## Verifying Expectations for DOI Builds

To verify that the provenance of a DOI build is authentic, expectations for a DOI build must be defined and checked.

Expectations for provenance verification are defined by source.

The source of truth for DOI builds is defined by the official-images [library manifest files](https://github.com/docker-library/official-images/tree/HEAD/library).
Library manifest files are managed by image maintainers and approved by platform administrators.
Contents of the manifest file define a set of inputs for each Official Image build (e.g. source repository, explicit full git commit hash, Dockerfile path, etc.).

The combination of expectations from library manifest files and GHA workflow context can be used to verify an image's provenance to determine if the artifact is genuine.

### Steps to verify DOI provenance

> :bulb: **Tip:** These generic steps are enumerated for informational purposes, see [#verification-summary-attestations](#verification-summary-attestations) on how to verify a precomputed summary of provenance verification

1. Check SLSA build level

   1. Verify the signature of the provenance attestation [DSSE envelope](https://github.com/secure-systems-lab/dsse) using the trust store published in [Docker's TUF root](https://github.com/docker/tuf)
   2. Verify the SLSA build level that maps to the `builder.id` and public key used to verify the envelope signature is at least `SLSA_BUILD_LEVEL_3` in the trust store
   3. Verify the statement's `subject` matches the digest and [PURL](https://github.com/package-url/purl-spec) of the target image
   4. Verify the `predicateType` is `https://slsa.dev/provenance/v1`

2. Check expectations
   1. Verify the statement's `subject` platform is one of the [applicable image platforms](#applicability) for the `builder.id`
   2. Verify that the `buildType` is `https://github.com/actions/buildtypes/tree/main/workflow/v1`
   3. Verify the external parameters
      > :memo: **Note:** We can ignore all workflow inputs except for the `buildId` input (this is the metadata used to invoke the build)
      1. Using the meta repository resolved dependency commit ref
         1. download the build metadata (`builds.json`) at the repository root
         2. filter metadata for specific `buildId`
         3. extract the `source.entry` data for verification
      2. Lookup the official-images submodule commit ref from the meta repository resolved dependency
         1. Map the statement `subject` package name (e.g. `pkg:docker/hello-world`) to the library manifest file (e.g. [docker-library/official-images/library/hello-world](https://github.com/docker-library/official-images/blob/HEAD/library/hello-world))
         2. Compare the contents of the library manifest file (source of truth) to the contents of the build metadata (obtained from `builds.json`)
            1. Verify that `GitRepo`, `GitCommit`, `GitFetch`, `Directory`, and `File` for the build match what is expected from the library manifest file
               > :warning: **Warning:** These values are often unique to the specific platform and tag of the image build and must be appropriately parsed and selected from the manifest
            2. If `GitCommit` fails, calculate the [reproducibleGitChecksum](#doi-build-reproducible-git-checksum) and verify it against the value in the build metadata
               > :memo: **Note:** `reproducibleGitChecksum` represents the build context by cryptographic digest of the source repository's Dockerfile path contents. In this case, the build is considered valid because the build context is the same for different `GitCommit` values.
            3. Verify all tags for subject references in the statement match expected tags for the artifact as defined in the library manifest file

#### DOI build reproducible git checksum

The source repository build context for each build can be identified by a digest of the git archive contents at the specified `GitRepo`, `GitCommit`, `GitFetch`, and `Directory` for a DOI build. This value is known as the `reproducibleGitChecksum`.

To calculate the value of `reproducibleGitChecksum`:

Prerequisites:

1. `git` version >= [2.40.0](https://git-scm.com/docs/git-archive/2.40.0)
1. tar scrubber to strip `uname` and `gname` headers (e.g. [tar-scrubber.go](./tar-scrubber.go))

Steps:

1. Clone the source repository at `GitRepo` from the library manifest file
2. Run `git archive` and scrub the tar output, using `GitCommit` and `Directory` from the library manifest file
   ```console
   git archive --format=tar --mtime='1970-01-01 00:00:00Z' <GitCommit>:<Directory> | go run tar-scrubber.go | sha256sum
   ```

Example:

```console
git clone https://github.com/docker-library/hello-world.git
```

```console
git archive --format=tar --mtime='1970-01-01 00:00:00Z' 3fb6ebca4163bf5b9cc496ac3e8f11cb1e754aee:amd64/hello-world | go run tar-scrubber.go | sha256sum
22266b0a36deee72428cffd00859ce991f1db101260999c40904ace7d634b788
```

Note that the output digest `22266b0a36deee72428cffd00859ce991f1db101260999c40904ace7d634b788` matches the value in [builds.json](https://github.com/docker-library/meta/blob/5171fea58d50da92eb4c3af3482a573a22197688/builds.json#L16977)

### Verification Summary Attestations

The DOI build process generates [Verification Summary Attestations (VSA)](https://slsa.dev/spec/v1.0/verification_summary) to communicate that the image has been verified at the build level obtained by the builder that generated the artifact.

The VSA generation process verifies expectations for DOI build provenance as outlined in [#steps-to-verify-doi-provenance](#steps-to-verify-doi-provenance) by use of attestation verification tooling and Rego policy stored in [Docker's TUF root](https://github.com/docker/tuf).

Consumers of DOI need not implement the extensive verification process for provenance and instead can verify the VSA as a minimal summary of the verification process as performed by Docker.

## Build Level Requirements

The table below describes how Docker Official Images (DOI) meet the [SLSA Build L3 (v1.0)](https://slsa.dev/spec/v1.0/) (Supply-chain Levels for Software Artifacts Build Level 3 spec version 1.0) requirements.

| Level                           | Requirement                                                                                                                                                      | Implementation                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Build L1: Provenance exists     | Software producer follows a consistent build process so that others can form expectations about what a “correct” build looks like.                               | The whole [DOI build process](https://github.com/docker-library/official-images) is open, and there are strict rules that must be followed to be considered part of DOI. For example, dependencies should be pinned and digests checked when package managers are not used. For more details, see the docs on [creating a new DOI](https://github.com/docker-library/official-images#contributing-to-the-standard-library) |
|                                 | Provenance exists describing how the artifact was built, including the build platform, build process, and top-level inputs.                                      | DOI GHA workflow builds generate a provenance attestation by the trusted control plane in accordance with the [official GitHub Actions buildType](https://actions.github.io/buildtypes/workflow/v1)                                                                                                                                                                                                                        |
|                                 | Software producer distributes provenance to consumers, preferably using a convention determined by the package ecosystem.                                        | Provenance attestations are distributed as standard OCI artifacts, and conform to open [In-Toto](https://in-toto.io/) and [SLSA](https://slsa.dev/spec/v1.0/provenance) specifications                                                                                                                                                                                                                                     |
| Build L2: Hosted build platform | Build platform runs on dedicated infrastructure, not an individual’s workstation, and the provenance is tied to that infrastructure through a digital signature. | [GitHub Actions](https://github.com/docker-library/meta/actions) runs the build workloads, and workload identity is used to sign provenance. Build triggering (which does not affect the build output) is a process that [runs on Jenkins](https://doi-janky.infosiftr.net/)                                                                                                                                               |
|                                 | Downstream verification of provenance includes validating the authenticity of the provenance.                                                                    | A Verification Summary Attestation (VSA) is created from a version controlled and securely distributed policy that validates the authenticity of the build-time attestations                                                                                                                                                                                                                                               |
| Build L3: Hardened builds       | Build platform implements strong controls to prevent runs from influencing one another, even within the same project.                                            | Each build is performed on a clean node isolated from all other workloads. Where caching is used, it is verified e2e using a trusted channel to transmit cryptographic digests.                                                                                                                                                                                                                                            |
|                                 | Build platform implements strong controls to prevent secret material used to sign the provenance from being accessible to the user-defined build steps.          | Secret key material is held in Cloud KMS within HSMs and cannot be read by any process. Workload identity is used to authenticate with the KMS for the signing of attestations and is limited to trusted processes initiated by the control plane and isolated from the build environment.                                                                                                                                 |
