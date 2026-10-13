> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Release preparation: retained originals and next JIT connection

## Implemented checkpoint

Commit `cb669c85` changes retention in
`data-plane/decision-gate-rs/src/main.rs`, not authorization.
`ReleasePreparation` now holds a private
`Arc<VerifiedReleaseAuthorizationHttpResponse>` wrapper instead of retaining
only a copied response body. It preserves the original request and response
bytes, response nonce, signed statement, signature and authenticated headers
from the existing verified HTTP exchange.

Clones share that exact allocation; equality compares retained identity, not
independently received responses. The wrapper's `Debug` output is redacted.
The existing zeroizing request/body owners remain alive until the last shared
owner drops. The original preparation deadline is unchanged by retention or
cloning, and existing profile, scope, policy-digest and expiry checks remain.

This does **not** admit a native caller, authorize JIT sealing, create an
approval, or establish a private review-opening right. The native signer is not
given a new generic signing or quotation operation.

## Verification status

The frozen `cb669c85` test build passed all **132 tests in 23 disjoint filters**,
with no failures or ignored tests: four new retention controls, six existing
signed-response controls and the unchanged 122-test proxy baseline. The four
new tests in `main.rs` are:

- `release_preparation_retains_exact_verified_originals`: exact bytes,
  allocations, nonce, authenticated headers and signed statement.
- `release_preparation_retains_shared_identity_and_redacted_lifetime`: shared
  ownership, distinct-exchange inequality, redaction and final-owner release.
- `release_preparation_retains_deadline_and_existing_profile_checks`: unchanged
  deadline and existing legacy/native/policy-aware refusal controls.
- `release_preparation_retains_actual_producer_join`: supplemental source guard
  joining the actual verified producer to retention after its existing checks.

These are typed retention controls and a source guard, not connected native
admission, cryptographic custody, hardware or deployed-workflow acceptance.

The offline Rust 1.88 test compilation completed in 316.375 seconds. Attached
test execution totals 31.085 seconds across the 23 groups; this excludes
staging, container lifecycle and listing, and is not application startup time.
The test binary is `824a300f4be95c3617d1df2f860f3b0847f0f5287c6472818354c5045f45d004`.
Source pins are `2f51e674205d0ffbaf56ee2f18e6b9116bfba0ea442d726e64f53a29feb19537`;
the test receipt is `5b02d6e36c7ecd9ec8a4b32cdd6163936cff09d5471570c11e8f0d636e1cf96e`.
The normal executable also compiled successfully, in 343.630 seconds:
`06e92a0070545d2d121d11f3a59936df232a9ab26f02de8324acc64d242da80f`.
Its compiler-input receipt records 516 inputs and has SHA256
`c1271ccfa1d2200729715b318df6c46c312613560cd4114a693bd230f4d9e213`.
This is a normal build, not execution or deployment of that executable.
All 26 build/test container cleanup receipts passed, with no remaining owned
containers. The existing cache/vendor and live deployment are unchanged.

Durable receipts and the pinned driver are retained under
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence/release-preparation-rust.Nsj7KuOq`.
The prepared artifact, frozen source and reusable build cache remain at
`/srv/catchplate-fast/tmp/serverware-release-preparation-rust.ZppP3tTr`
for subsequent integration; no future build or deployment should use them
without checking the committed compiler-input identity.

## Next connected path: atomic reserve with a pending JIT child

The real proxy path is `request_release_authorization` → the app's versioned
reserve endpoint → `release.reserve`. Its missing-grant branch must create the
pending review within the same authority transaction. Wiring only standalone
`jit.request` is insufficient: the nested private DB helper does not enter that
public writer wrapper, and Rust refuses the legacy standalone JIT composition.

The proposed next cut, not yet implemented, is:

1. Thread the genuine authenticated request/session owner and original deadline
   into buffered release preparation. A principal string, canonical JSON or
   copied success verdict cannot substitute for that owner. After the signed
   `prepare_release_policy` exchange, retain and independently verify its exact
   originals before native sealing; complete sealing and reserve under the
   same original bounded operation, with no deadline renewal.
2. Define a versioned parent/child binding. Public `release.reserve` arguments
   carry the exact child JIT commitment; literal native pair/proof travels
   separately from public arguments. The native statement binds the parent
   request, child request and sealed pair. Do not put the pair hash into its
   own request commitment or silently reuse standalone JIT identity domains.
3. Keep `Prepared` private to the actual broker. One admitted request spends its
   seal attempt before helper I/O; preparation, purpose-specific signing and
   quotation repeat the same-owner, identity and original-expiry checks.
   Preserve separate canonical-wrapper and inner-document commitments.
4. Independently admit the literal native proof before storage. Fold the pure
   pending-child transition, both exact opaque values and admitted evidence into
   the parent writer transaction: no second dispatch or preliminary insertion.
   Verifier receipt identities come from the admitted verifier, not renamed
   native-producer fields. Stored pending expiry cannot exceed the original
   sealed-document expiry.

The current release receipt kernel does not implement this branch: its mutation
roster excludes pending approval/opaque creation, its denial rules do not admit
those mutations, and its no-attempt result has no pending approval ID. These
contracts need an explicit connected transition, not a relaxed receipt check.

Required follow-up tests enter actual versioned reserve and cover exact
parent/child/proof joins, atomic rollback, wrong caller/current policy, original
expiry, one-use/uncertain-result refusal and absence of private plaintext in
retained public plans. Authorized private opening still needs current actor,
session, policy and exact retained custody admission; it remains unconnected.

No new pilot, live enabling, deployment or provider action is part of this
retention change or this design note.
