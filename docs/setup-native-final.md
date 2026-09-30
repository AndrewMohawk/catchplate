# Scoped native Setup completion

This source connects the completed native hardware/proxy chain to an independent final-authority producer, a protected two-person consumption, the existing Setup session, and the portal. It is not runtime acceptance. No build, browser, provider, installation, signing or end-to-end test has been performed for this batch.

## Actual producer and consumer

1. The original Setup owner, still holding literal credential_owner and policy_author roles, supplies a fresh hardware assertion to `setup.native-final.prepare`. The kernel re-reads the exact completed hardware row and all native enrollment, authenticated host CA readback, canary, runtime and source audit originals. It rechecks the active credential/currentness root and actual current native publication, then inserts one protected final challenge. It never contacts an issuer automatically.
2. The operator transfers the exact canonical issuer request through the independently approved channel to `scripts/issue_native_setup_final.py`. The producer re-verifies the original native quote, both independently signed C25 receipts, native enrollment/key/leaf, authenticated host readback and trusted collector capture. It signs only its computed native-final-authorization payload, using the separately provisioned key matching the cold finalAuthority pin. It does not sign uploaded success claims or claim that the challenge has already been consumed.
3. A different current attestation_reviewer imports that exact public receipt and uses a fresh hardware assertion for `setup.native-final.complete`. Independent verifier and planner both reverify the original chain and final signature. The kernel rechecks current rows and completed source audits, consumes the original challenge once, and records native_completion_pending_audit. The owner cannot review their own final receipt.
4. The same reviewer explicitly invokes `setup.native-final.settle` only after the actual completion audit is included. It rechecks the original interval, current policy/credential/publication, reviewer role/key and the original reviewed hardware trust high-water. In one protected CAS it advances the final row to revision2 and the actual Setup session from revision3/credential_activated to revision4/native_scoped_complete with terminal status complete. Legacy receipt columns remain untouched. The old measured-host completion route cannot consume this native phase.

The native portal and the existing Setup summary both consume this explicit state and label it **Scoped native Setup complete**. This is historical completion for enclave-hardware-and-proxy-only evidence and a trusted-host-local CA association. measuredHost, proxyReady and okForAction remain false. This record is not a traffic capability, does not replace per-request credential/policy enforcement and does not narrow full-project acceptance.

## Fixed independent final-authority installation

Settlement also creates the real sequence5 native Setup transition event after requiring the four original Setup events to be audited. That new event enters the existing Setup audit outbox as pending; no audit success is fabricated. Lookup exposes only a read-only observation of actual completion-audit inclusion, and the portal requires it before offering the one settlement attempt. The HTTP caller refuses before dispatch if inclusion is absent; the kernel still independently proves it. A metadata-audit status is not an operator-supplied permission flag.

The new source-selected entry is `issue_native_setup_final.py`, isolated Python `-I -B`, no arguments. Its fixed root-protected named configuration is `/etc/serverware/setup-native-final-authority.json`; role is `final-authority`. It uses the existing exact9 `setupNativeIndependentVerifierConfiguration/v1` layout. FD3 is that actual root0400 original. FD4 is an independently assigned final UID/GID-owned, fully sealed0600, zero-link exact32-byte Ed25519 seed. FD5 is a distinct equivalently sealed public request, at most4MiB. No key is generated, derived from workload/CA keys, sent through claimant RPC or baked into an image.

The request is exact6: actor_id, control_plane_configuration_digest, credential_policy, maximum_final_nanos, hardware_original, challenge_original. Original canonical ASCII strings remain literal. Same retained process/PIDFD, hardening, original boot/time namespace and at-most30-second BOOTTIME operation are checked through bounded FD1 write-only-pipe emission. The result is canonical no-LF envelope2, at most16KiB. The fixed domain is `serverware/setup-native-final-authority/v1\0` followed by canonical payload16. Challenge12 and receipt16 are specified in [the schema](../schemas/setup-native-final.v1.schema.json).

The independently signed control-plane configuration explicitly enables the three native-final operations for verifier and planner and adds `setupNativeFinalPolicy` exact3: schema `serverware.setupNativeFinalAuthorityPolicy/v1`, credentialPolicy, maximumChallengeNanos. Credential policy equals the actual admitted native hardware policy; maximum is positive1–300seconds and no greater than its bound. The separately pinned C25 finalAuthority must remain independent from hardware/proxy, control-plane, workload, collector, CA, host and issuer keys/providers.

An actual fixed external supervisor, immutable runtime packaging, installed trust/configuration and opaque seed handoff remain deployment/producer prerequisites; this script is not a claim they already run. The hardware/proxy packaging lane can reuse these same ownership mechanics with this third explicit profile. The original independent issuer interval is never copied into a refreshed deadline.

## HTTP and portal

POST `/api/setup/native-final/{options,prepare,complete,settle,lookup}`, strict OIDC cookie/Origin/CSRF, no bearer or admin-token fallback. All bodies use `setupNativeFinalRequest/v1` and sessionId.

- options: adds phase prepare or complete; complete also carries receiptOriginal. Returns exact purpose-bound passkey options.
- prepare: adds assertion. Returns201 with public final state and exact bundle.
- complete: adds receiptOriginal and assertion. Returns200 pending audit.
- settle: no receipt upload or new permission DTO; selects the actual retained receipt. Returns200 only after audited native scoped completion.
- lookup: read-only for the actual owner or current attestation_reviewer. Recovers the exact retained challenge/request/receipt and historical scoped state, never contacts the issuer or repeats a mutation.

Bodies are capped at32KiB, responses at4MiB. Aggregate original nesting is admitted before reservation. The portal preserves originals in memory, uses exact-integer JSON, writes nonsecret per-actor/session/phase attempt markers before each dispatch, and never clears those markers. Authentication/session/page changes clear the held originals. A lost201/200 is an unknown outcome, not absence; use lookup. Missing audit inclusion or expired original evidence cannot be repaired by settlement, a new challenge or arrival-time permission.

## Remaining usable-flow boundaries

A real normal request still needs the actual native dispatch, provider-send and terminal effect owners; this Setup phase does not synthesize their receipts. A successful controlled pilot additionally requires the real native cohort/key/time/verifier installation, independently provisioned assignments and keys, protected control-plane/audit services, actual enrollment/host installation and one end-to-end credential-controlled request/decision/response. First build and deployment evidence remain unperformed. Full production and measured-host acceptance are unchanged.
