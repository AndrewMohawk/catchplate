# Remaining pilot commissioning

This is the remaining operator sequence, **not a working-pilot claim**. The
isolated development stack has not completed policy commissioning, demo seeding,
verified CA handoff or the two proxy requests. Keep it loopback-only and use only
synthetic credentials. Source checks, images, healthy dependencies and a loaded
UI do not establish an accepted application flow.

## Required inputs and services

The existing `trusted-host-local` authority mode permits an honestly co-located,
non-TEE pilot. Nitro, real provider credentials and production hardware evidence
are not prerequisites for the synthetic flow. That does not make the current
Compose file a complete launcher: its authority commands lack the real
per-invocation process observation and signed late-input delivery path.

The [local startup implementation](trusted-host-local-startup.md) separates
actual Python/pathname execution from native static-ELF/descriptor execution.
It connects the retained real child, protected static inputs and late signed
launch documents. This source connection has not commissioned the pilot.
The remaining prerequisite is a genuinely installed signed local authority
package, with actual installation evidence and scoped trust inputs; existing
artifact/provisioning commands produce unsigned packages/plans, not those
effects. The genuine first-policy prepare/audit/finalize caller must also be
connected. Do not manufacture observations or receipts to fill these gaps.
Native production admission remains separate.

Required components, with actual separately scoped identities:

- PostgreSQL with separate, correctly restricted metadata/audit runtime and
  authority roles, plus the offline administrative connection. The exact source
  schema, function and role checks are in the [database installer](../serverware/db.py).
  A shared development superuser DSN is not a replacement for those role contracts.
- The real authority runtime and its verifier, planner, planner-writer, issuer
  and executor, with their admitted configurations, actual measurements,
  credentials, replay protection and required independent audit service.
  [AuthorityRuntimeClient](../serverware/authority_service.py) consumes protected
  `SERVERWARE_POLICY_AUTHORITY_RUNTIME_ROOT_PUBLIC_KEY_FD` and
  `SERVERWARE_POLICY_AUTHORITY_RUNTIME_TRUST_FD`; a JSON success flag is not trust.
- Independently supplied signing/trust identities, issuance and attestation
  evidence, TLS pins and audit identity/signer bindings required by that source.
  The production first-policy maintenance ceremony additionally requires
  control-plane custody, enrollment and current RBAC owners with enrolled
  hardware operators. The explicitly development-only offline file installer
  below does not impersonate that ceremony.

Keep private keys and administrative DSNs in the operator's protected delivery
mechanism, not chat, command transcripts or published evidence. Record nonsecret
source/image identities and public pins. Missing authority inputs are a stop
condition, not permission to invent receipts or enable a fallback.

## Ordered execution

1. **Provision roles, then bootstrap metadata offline.** The explicit
   [role helper](../scripts/provision_metadata_roles.py) accepts `--plan` without
   connecting and `--apply` with the existing protected admin DSN. It requires
   `metadata-bootstrap`, PostgreSQL selections and configured runtime/executor/
   verifier names. It creates only absent source-selected roles in one
   transaction; collisions refuse instead of altering existing accounts.
   LOGIN roles have no passwords, memberships or schema grants. This is a role
   foundation, not usable authentication, credential issuance or DB readiness.
   The isolated pilot's 13 roles were actually created and read back from
   `6a69d94b`; repeated apply refused without changing their attributes.
   Authentication and actual authority pins must still be provisioned.
   Then use the fixed
   [bootstrap entrypoint](../scripts/bootstrap_metadata_store.py) only after its
   required operator configuration is present. It requires the separate
   `metadata-bootstrap` process selection and delegates to
   `db.init_db(bootstrap_contract_id="serverware.metadataStoreBootstrap/v1")`.
   It does not provision roles, generate pins or admit authority services.
   Ordinary control-plane startup remains non-DDL and must subsequently verify
   the exact installed contract. A bootstrap failure is not a usable database.
2. **Prepare genuine demo-policy genesis.** Have the selected authority approve
   the exact signed policy matching
   [demo_policy_bundle](../serverware/policy_bundle.py) for `cred-demo-bearer`.
   Invoke the existing `prepare_policy_authority_genesis` operation through its
   actual authority path. Obtain the real transition's independently verified
   audit inclusion, then `finalize_policy_authority_genesis`. Retain the exact
   preparation, inclusion and finalization originals. No direct SQL insert,
   local signature alone or synthetic verifier response establishes this state.
3. **Materialize that same signed policy.** For the synthetic development pilot,
   the fixed [offline installer](../scripts/materialize_development_policy_genesis.py)
   consumes an inherited root-owned read-only/sealed policy FD, its SHA256 and
   the actual genesis preparation/finalization digests. Invoke it with
   `python -I -B`, root, explicit `SERVERWARE_PROCESS_MODE=metadata-bootstrap`,
   a development release and a non-production image. Existing public signing
   trust and the protected `SERVERWARE_POLICY_FILE_GENESIS_DSN_PATH`/`_SHA256`
   configure its separately restricted read-lock connection; admin/executor
   DSNs are forbidden. See `--help` for the closed public argument list.
   It verifies exact signed demo semantics and the genuine finalized chain,
   holding the same actual PostgreSQL transaction through absent-only
   publication, fsync and readback. The active target must be absent and its
   publication journal absent/empty. No policy signing, authority advance,
   replacement, manufactured receipt or production guard change occurs.
   Failure is **not rollback**: stage or installed files may remain; valid
   signed/current bytes may independently load. Preserve them and inspect the
   outcome; never automatically retry, delete or restore. Success requires
   known cleanup within the original deadline; an external watchdog must bound
   kernel/filesystem stalls. Then perform a fresh normal application startup.

   Production instead uses the separately admitted cold
   [finalized-genesis maintenance path](control-plane-policy-file-genesis.md)
   and its [operator portal](control-plane-policy-genesis-portal.md), with the
   original signed maintenance scope and distinct operators' fresh hardware
   approval/consume ceremonies. Settle the actual outcome and stop maintenance
   before fresh normal startup; never promote maintenance into service.
4. **Seed demo data once.** After normal startup accepts the installed policy,
   use the existing authenticated `/api/demo/seed` endpoint. Its
   [admission helper](../serverware/demo_seed_policy.py) requires current committed
   authority and exact demo semantics before any credential/route write. It
   neither publishes policy nor advances its sequence. A
   `409 demo_policy_commissioning_required` means stop and correct commissioning;
   do not switch to SQLite/non-atomic mode or retry with manufactured state.
5. **Complete the CA and gate startup.** Keep the frozen Rust executable SHA
   pinned. Wait for the synthetic HTTPS upstream and CA, then use the existing
   [verifier-mediated CA installer](../scripts/install_verified_ca.sh) under the
   isolated project's environment. Its container verification URL uses port
   3000; the host UI uses 13000. Require actual verification success before
   starting the exact gate image with `--no-build --pull never`. Preserve TLS,
   workload authentication, policy denial and credential redaction.
6. **Verify the user flow.** Follow the [pilot walkthrough](development-pilot.md):
   inspect the seeded UI, then run its public-CA-bound checker. Require both a
   real `/echo` response showing the synthetic upstream credential marker with
   no raw credential/proxy identity, and `/not-allowed` returning the expected
   policy denial. Finally verify project-scoped stop/start with data preserved.

Retain bounded results and exact artifact identities for each completed step.
On uncertainty, preserve partial state and diagnose that step; do not reseed,
delete volumes, bypass authority checks or claim production/TEE custody.
