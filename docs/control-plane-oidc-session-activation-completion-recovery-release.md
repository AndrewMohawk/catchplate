# Fresh recovery intent and proof preparation

The consume completion-recovery path can continue acknowledged originals into
a genuinely signed release intent and a privately produced, independently
verified release proof. This is source integration, not observed execution or
token delivery. It does not select a private release checkpoint or change a
browser cookie.

The fixed POST routes are:

- `/api/auth/session/activation/consume/completion/recovery/release-proof/options`
- `/api/auth/session/activation/consume/completion/recovery/release-proof`

Both use the existing strict 64 KiB recovery request carrier. The server selects
the target from retained originals and requires actual old-token possession,
current user/credential/role/trust checks, Origin/CSRF, fresh WebAuthn and configured
two-person approval. The distinct `release-intent-proof` binding and schema make
this a different authorization from completion-only reconciliation. Neither
profile, authority originals, private keys nor a release checkpoint comes from
browser JSON.

## One original call

```text
fresh purpose-bound actor
  -> select original acknowledged completion+hints OR separate reconciliation
  -> genuinely admit signed completion/ACK and exact historical target
  -> derive expectations from signed activation/consume arguments
  -> same durable intent slot: one signature OR original re-admission
  -> same durable proof slot: one setup/proof exchange OR original re-admission
  -> retain and genuinely verify exact originals
  -> normal actor/trust cleanup
  -> historical preparation response; session state still unknown
```

A spent slot without its required originals is terminal uncertainty. No new
actor, restart or configuration can create a second slot for that target.
Existing uncertain completion outcomes remain immutable; separate reconciliation
is reselected and compared, never substituted as an unsigned success object.
This action performs no completion socket exchange and never repeats SQL.

New signing and proof contact require independently configured proof-input setup
before their durable claims. An already retained proof from the original LIVE
flow may be admitted read-only without a setup record; that does not permit a
new contact. Records must belong to the currently admitted source cohort. This
connection is not an implicit cross-version migration.

Unsigned packet, effects and encrypted-delivery hints are expectations only.
The independent private proof must match them. Genuine original signature
admission, dedicated cold intent-key custody and distinct root-pinned proof
enrollment remain necessary. Original delivery expiry remains a hard limit;
neither fresh user permission nor historical admission retimes it.

## Bounds and cleanup

Before the first target body, the actor reserves future input derivation,
intent/proof processing, reconciliation reload and receiving representations
under the original 64 MiB inventory. The input derivation lane is 4 MiB; the
intent/proof output lane is 8 MiB, with measured cold originals accounted
separately. These restrictive lanes may reject otherwise protocol-sized data.
They do not add a work allowance or claim a measured Python heap/RSS limit.

The proof transport's optional aggregate response cap only tightens its existing
wire maximum; it is checked after the length header and before any body
allocation. All child guards preserve the original work and narrowing clocks.
The final genuine proof guard is retained separately through normal cleanup,
never fed back into its own actor ancestor.

The public response contains no original controls, proof, hint or token. It
reports `release-intent-proof-retained`, `sessionState: unknown`,
`tokenReleased: false` and `automaticRetryAllowed: false` only after normal
coordinator return. An error does not establish whether an earlier effect ran.

## Remaining delivery boundary

A later continuation requires fresh release-purpose-bound authorization. It
must not broaden this preparation-only approval or reuse its closed actor.
Within that fresh live scope it must independently root-admit the appropriate LIVE
checkpoint-zero first-release profile or RECOVERY checkpoint-one retained-outcome
profile, perform the protected exchange, recheck current authentication and
guard the final cookie send. Missing local intent/outcome and a reconstructed
outcome prove neither private-store existence nor absence and cannot select
that profile. Newly signing an intent changes its evidence identity.

Unattempted consume, portal actions, independent resources, deployment and every
production acceptance gate remain open. No build, tests, runtime execution or
AWS provisioning is implied by this source checkpoint.
