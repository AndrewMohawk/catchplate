> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Explicit release stages

`production-release-proof` verifies an already prepared final-v1 result using
`finalize-production-final-v1`. It no longer builds, tests, publishes, signs,
deploys, installs a launcher, or starts the legacy Docker NSM readiness service.
Missing independent evidence fails closed. A verified historical result is not
an action authorization.

Each stage below runs separately in the indicated owner's environment. There is
no aggregate command that crosses these authority boundaries. The repository
provides candidate-building and evidence-consumption tools; running them on
catchplate-host does not establish independent administration or production provenance.
Use separate Make invocations; do not submit several release stages together
with `make -j`. Transfer signed reports byte-for-byte, preserving their detached
signatures. Signing and deployment consume those reports without regenerating them.

| Stage | Operation | Required evidence/output |
| --- | --- | --- |
| Clean source | `make production-source-capture` | Clean Git commit and tree; deterministic archive, file list, hashes, modes and source manifest under `production-dependencies/cache/source-contract`. Retain the printed capture identity. |
| Engineering preparation and tests | Approved v12 controller build, then its sequential no-build lanes | Exact source/artifact binding and terminal cleanup receipt. Existing `coder-v12-*` commands submit operations to the separately installed controller. Developer Compose checks remain narrower diagnostics. |
| Isolated release build | `make production-release-build` in a fresh release-builder workspace | Reviewed immutable offline dependency snapshot; production image record, Python runtime and launcher artifacts. The owner must additionally supply isolated SLSA v1.2 provenance and OCI SBOMs. The target rejects existing outputs before it builds anything. |
| Registry publication | `make production-release-publish` in the publisher environment | Registry digest readbacks and image environment file bound to the captured build. No rebuild. |
| Independent reproduction | Separately administered source-to-OCI and OCI-to-EIF builds; `make validate-reproducible-builds` consumes their reports | Independently trusted signed reports. Different local key names or builder IDs are insufficient. |
| Signing | `make production-release-sign` in the signing environment | Verified reproduction, release provenance and KMS-backed image signatures with transparency evidence. No build, publication, or deployment. |
| EIF and signed release record | Independent Nitro release authority | Actual EIF/PCR0/PCR1/PCR2, runtime and policy/configuration roots, source/SLSA/OCI/SBOM bindings, verifier version, release sequence and witness checkpoint. This external production stage is still required; local compatibility manifests do not implement it. |
| Deployment preparation | `make production-release-deploy` on the authorized production environment | Existing enrollment, policy activation, reproduction and preflight evidence; configured KMS materials, deployed artifacts and installed launcher. This retains the legacy host-readiness installation path; it does not implement full enclave custody. |
| Trusted-host readiness, if needed | `make run-production-readiness-final` explicitly | Legacy host-readiness diagnostics only. This service cannot produce final-v1 production acceptance. |
| Independent verification | `make prepare-production-final-v1`, external authority response, then `make production-release-proof` | Fresh independently verified Nitro evidence, pinned trust roots and role registry, retained exact signing request, independent signing response and final-v1 result. |

Do not transfer production private keys to the source checkout or build worker.
Move only immutable artifacts and the necessary public evidence between stages.
The [release interoperability notes](release-interoperability.md) describe the
representation-preserving Sigstore boundary and the remaining distinction
between static Compose topology and verified runtime identity/lifecycle.
The dependency owner must publish a new wheelhouse for the current
`cryptography==50.0.0` lock before the production build can proceed. Both dependency
manifests must identify the same reviewed snapshot; changing pins without
publishing and verifying the corresponding artifacts is not a repair.

Splitting the commands removes the old automatic mutation graph. It does not
close the remaining production requirements in `goal.md`: actual enclave TLS and
credential custody, independently operated authorities and rollback state, live
provider and physical-authenticator ceremonies, and the complete signed release
chain still need implementation and execution evidence.
