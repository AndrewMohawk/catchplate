# Co-located local RBAC witness

The explicit local enrollment and startup profiles are source-connected. A
separate local PostgreSQL cluster and TLS material are prepared, but its witness
schema and signed enrollment are not provisioned. This is not a completed pilot.
Existing independent v1/v2 profiles
and their production guarantees are unchanged.

`catchplate.trustedHostLocalRbacWitnessEnrollment/v1` is signed by the existing
offline RBAC enrollment-root mechanism in its own schema signature domain,
inside `catchplate.signedTrustedHostLocalRbacWitnessEnrollment/v1`. Its exact
`assurance` says trusted-host-local, co-located, not hardware-backed, not
independently administered, and not resistant to joint rollback. Its
`faultDomainScope` is `separate-local-cluster-storage`: the distinct labels
describe actual separately retained local cluster storage, not different host
administrators or physical independence. The operator must provision and
verify that storage separation; labels alone do not prove it.

`catchplate.trustedHostLocalRbacWitnessStartup/v1` carries the existing eight
startup fields and only the matching local signed enrollment. It has no
recovery permission. The runtime requires protected original FDs plus genuine
already-admitted local authority launch and signed Service6 policy, or genuine
control-plane custody and its admitted local RuntimeTrust evidence. A dev
environment variable is not admission. The production image marker, production
image selection or non-development release channel refuses this profile.

Both original validity and runtime admission remain live checks. The RBAC root
must still differ from the configuration/runtime root. Actual metadata and
witness cluster IDs must differ. TLS 1.3 verify-full, pinned reader/writer
certificates, fixed restricted PostgreSQL roles/procedures, initial root recipe,
current-head locking, exact predecessor/CAS, pending refusal and definite commit
checks are unchanged. There is no implicit initialization, adoption, reset,
retry, current-head invention, or metadata-writer promotion.

Offline `authority_rbac_witness.provision` accepts the signed local profile only
in non-production development mode and applies the same initial-only fixed v1
schema/procedures. It still refuses an existing namespace. No provisioning has
been performed for this profile. Required deployment inputs remain a genuinely
separate cluster/storage, dedicated enrollment root and TLS reader/writer
credentials, independently selected initial state, and exact startup FD joins.

For the parked local verifier/planner/executor entrypoint only, the nested
material map is source-fixed: root `240`, TLS root `241`, client certificate
`242`, client key `243`. The child first proves all four slots unoccupied and
outside its actual inherited setup/control roster, acquires its own empty
sealed reservations, then replaces only those exact reservations with its
fixed-role credential originals. The startup original pins those four target
numbers and exact hashes; the actual observed descriptor roster and existing
cold owner still check them. Caller-owned descriptors are never adopted or
overwritten. Native, ordinary non-parked, and control-plane delivery keep their
existing behavior. These slots do not manufacture a witness or credentials.

The trusted host administrator can access both sides and may roll them back
together. This profile makes no claim against that threat. Production
[independent RBAC currentness](rbac-independent-currentness.md) still requires
an independently administered witness and its separate deployment evidence.

For initial local bootstrap only, the caller selects a microsecond-aligned UTC
timestamp inside the unchanged original approval window. The source-owned
initial RBAC recipe includes that exact timestamp so the separately signed
witness expectation can precede metadata creation without inventing an observed
head. This is a programmatic development-only input, not a CLI/environment
override; existing authority rows or legacy bindings refuse it. The default
bootstrap retains its database-clock behavior. After bootstrap, actual metadata
roots and state must match the witness expectation before cohort publication.
