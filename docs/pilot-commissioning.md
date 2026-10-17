# Remaining pilot commissioning

This is the remaining operator sequence, **not a working-pilot claim**. The
isolated development stack has not completed policy commissioning, demo seeding,
verified CA handoff or the two proxy requests. The browser uses the protected
[homelab HTTPS ingress](homelab-deployment.md); raw proxy and management listeners
remain private. Use only synthetic credentials. Source checks, images, healthy dependencies and a loaded
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
package, with actual installation evidence and scoped trust inputs. New
[local snapshot/signing/installation commands](trusted-host-local-installation.md)
and the genuine foreground first-policy caller connect those code paths, but
have not performed a complete installation or policy transition. Missing
upstream evidence producers and a capable dedicated filesystem remain explicit
gaps. Do not manufacture observations or receipts to fill them.
Native production admission remains separate.

Required components, with actual separately scoped identities:

- PostgreSQL with separate, correctly restricted metadata/audit runtime and
  authority roles, plus the offline administrative connection. The exact source
  schema, function and role checks are in the [database installer](../catchplate/db.py).
  A shared development superuser DSN is not a replacement for those role contracts.
- The real authority runtime and its verifier, planner, planner-writer, issuer
  and executor, with their admitted configurations, actual measurements,
  credentials, replay protection and required independent audit service.
  [AuthorityRuntimeClient](../catchplate/authority_service.py) consumes protected
  `CATCHPLATE_POLICY_AUTHORITY_RUNTIME_ROOT_PUBLIC_KEY_FD` and
  `CATCHPLATE_POLICY_AUTHORITY_RUNTIME_TRUST_FD`; a JSON success flag is not trust.
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
   `db.init_db(bootstrap_contract_id="catchplate.metadataStoreBootstrap/v1")`.
   It does not provision roles, generate pins or admit authority services.
   Ordinary control-plane startup remains non-DDL and must subsequently verify
   the exact installed contract. A bootstrap failure is not a usable database.
2. **Prepare genuine demo-policy genesis.** Have the selected authority approve
   the exact signed policy matching
   [demo_policy_bundle](../catchplate/policy_bundle.py) for `cred-demo-bearer`.
   Use the fixed [foreground caller](../scripts/commission_development_policy.py)
   with its four pre-admitted descriptors and the actual `AuthorityRuntimeClient`.
   It sends `policy.genesis.prepare`, retains the actual result, and waits for
   its supervisor to fill/seal the reserved late request with independently
   verified audit inclusion and fresh bound WebAuthn approval. It then sends
   `policy.genesis.finalize`, bound to that same live preparation. Retain the exact
   preparation, inclusion and finalization originals. No direct SQL insert,
   local signature alone or synthetic verifier response establishes this state.
   The existing semantic-to-kernel business-intent normalization is used only
   on a temporary validation copy; caller originals remain unchanged. This
   caller does not supply the missing evidence signer/registration service.
3. **Materialize that same signed policy.** For the synthetic development pilot,
   the fixed [offline installer](../scripts/materialize_development_policy_genesis.py)
   consumes an inherited root-owned read-only/sealed policy FD, its SHA256 and
   the actual genesis preparation/finalization digests. Invoke it with
   `python -I -B`, root, explicit `CATCHPLATE_PROCESS_MODE=metadata-bootstrap`,
   a development release and a non-production image. Existing public signing
   trust and the protected `CATCHPLATE_POLICY_FILE_GENESIS_DSN_PATH`/`_SHA256`
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
   [admission helper](../catchplate/demo_seed_policy.py) requires current committed
   authority and exact demo semantics before any credential/route write. It
   neither publishes policy nor advances its sequence. A
   `409 demo_policy_commissioning_required` means stop and correct commissioning;
   do not switch to SQLite/non-atomic mode or retry with manufactured state.
   The selected `live-homelab` guest continuation performs this one request
   itself before waiting for CA publication. It uses the retained operator
   credential, validates the response's actual policy hash/sequence and demo
   credential ID, and does not print the response. Only empty TCP readiness
   probes may repeat; the POST is never replayed after timeout or failure.
   This removes a manual seed-click race without changing the endpoint's
   administrator, development-mode or committed-policy requirements. It is
   implemented startup behavior, not evidence that seeding has run.
5. **Complete the CA and gate startup.** The selected launcher runs the exact
   retained Rust executable in the same guest and trusted UID as the normal
   control plane, using the guest's separately measured loader/libraries. This
   explicit local trust boundary keeps the CA private key in the guest; it is
   not production process or enclave isolation. Six separately scoped service
   credentials replace the former shared-token assumption. The existing
   [CA verifier](../scripts/verify_attestation.py) must accept the actual normal
   app at guest port 3000 before the gate starts. Do not launch the older Compose
   gate against unrelated CA or policy files. The host proxy is loopback 18080;
   the management listener stays inside the guest. Require genuine CA
   verification, workload authentication and signed policy enforcement.
6. **Verify the user flow.** Follow the [pilot walkthrough](development-pilot.md):
   inspect the seeded UI, then run its public-CA-bound checker. Require both a
   real `/echo` response showing the synthetic upstream credential marker with
   no raw credential/proxy identity, and `/not-allowed` returning the expected
   policy denial. Finally verify project-scoped stop/start with data preserved.

Retain bounded results and exact artifact identities for each completed step.
On uncertainty, preserve partial state and diagnose that step; do not reseed,
delete volumes, bypass authority checks or claim production/TEE custody.
