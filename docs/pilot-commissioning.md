# Remaining pilot commissioning

This is the remaining operator sequence, **not a working-pilot claim**. The
isolated development stack has not completed policy commissioning, demo seeding,
verified CA handoff or the two proxy requests. Keep it loopback-only and use only
synthetic credentials. Source checks, images, healthy dependencies and a loaded
UI do not establish an accepted application flow.

## Required inputs and services

The operator must provision these independently; ordinary development Compose
does not create them:

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
  Existing control-plane custody, enrollment and current RBAC owners are also
  required for the first-policy maintenance ceremony, with enrolled operators.

Keep private keys and administrative DSNs in the operator's protected delivery
mechanism, not chat, command transcripts or published evidence. Record nonsecret
source/image identities and public pins. Missing authority inputs are a stop
condition, not permission to invent receipts or enable a fallback.

## Ordered execution

1. **Bootstrap metadata offline.** Use the fixed
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
3. **Materialize that same signed policy.** Use the separately admitted cold
   [finalized-genesis maintenance path](control-plane-policy-file-genesis.md)
   and its [operator portal](control-plane-policy-genesis-portal.md). It requires
   the protected genesis read-lock connection, original signed maintenance
   scope, current positive genesis chain, and distinct operators' fresh
   hardware-bound approval/consume ceremonies. It publishes bytes; it does not
   create genesis. Settle the actual outcome, stop maintenance, then perform a
   fresh normal startup. Do not promote the maintenance process into service.
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
