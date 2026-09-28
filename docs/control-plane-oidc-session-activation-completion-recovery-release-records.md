# Completion recovery preparation and release records

This source-only continuation stores DATA in the existing consume-family intent
and proof slots, followed by separately authorized LIVE grant acquisition or
guarded use of the existing RECOVERY-policy family and global dispatch records.
It does not authenticate completion, sign an intent, request a
proof, grant release authority, open a token or establish current session state.
The fresh actor and genuine original admission remain the caller's responsibility.
See [public recovery](oidc-session-activation-public-recovery.md) and the separate
[completion reconciliation records](control-plane-oidc-session-activation-completion-recovery-records.md).

## Fixed custody interface

The custody client and journal expose these explicit methods:

- `load_oidc_session_activation_completion_recovery_release_records`
- `claim_oidc_session_activation_completion_recovery_release_intent_attempt`
- `append_oidc_session_activation_completion_recovery_release_intent`
- `claim_oidc_session_activation_completion_recovery_release_proof_attempt`
- `append_oidc_session_activation_completion_recovery_release_proof_setup`
- `append_oidc_session_activation_completion_recovery_release_proof`

Every method takes keyword-only `finalization_digest`,
`activation_authorization_digest`, `completion_originals`,
`reconciliation_digest`, `work`, `current` and optional
`maximum_original_bytes`. Appends also take `originals`: signed intent raw1,
setup bootstrap raw1 or proof response raw4. The loader returns exactly
`(intent_claim, intent, proof_claim, setup, proof)`, with absent members `None`.
Members are existing `ConsumeRecord` objects, never admitted authority.

`completion_originals` is exact acknowledged consume raw6. A `None`
`reconciliation_digest` selects the existing completion raw4 plus hints raw2;
otherwise it selects the exact separate consume-phase reconciliation response
record digest. The journal re-reads the actual selected immutable files and
requires byte-for-byte equality. It verifies record identities and associations,
not receipt signatures or hint semantics. The caller freshly verifies those
originals before relying on them.

The separate reconciliation's unique finalization/consume-phase claim and
response allow the release suffix after a retained SQL-claimed prefix, even when
the original completion/hints are absent or uncertain. The original prefix must
remain ordered; the release suffix must also remain ordered. Recovery checks the
exact reconciliation metadata and original predecessor association without a
recursive scope callback. No missing SQL outcome, completion outcome or hints
are synthesized, and no old record is replaced. Existing normal publication
methods and all record encodings/digest domains remain unchanged. Temporal
history is not a cross-version migration: new publication still requires the
currently admitted source cohort.

## Irreversible slots and read-only reuse

Intent and proof claims use the same global consume-family names and slot as
the original activation flow. A fresh actor, different reconciliation locator,
process restart or uncertainty does not permit another claim. Only a newly
successful claim made by this exact work permits its corresponding append.
Setup and proof share the single proof claim; new proof publication in this
continuation requires durable setup. Read-only admission of an already retained
LIVE proof without setup remains possible; the loader does not create setup or
change the existing LIVE path.
Completed append removes that in-memory continuation, which is never recovered.
The in-memory association keeps only work and the fixed locator, not raw6 bodies.

An existing claim without its output is terminal uncertainty, not permission to
sign or contact a worker again. Existing outputs may only be read and genuinely
re-admitted. Raw intent/setup/proof bodies are durably stored before the caller's
semantic branch; a stored status or signature-shaped object is not a successful
proof. These records contain no old/new token, cookie, WebAuthn assertion or
public recovery request.

## Fresh LIVE release acquisition and dispatch

The .213 continuation has a distinct fresh RELEASE-purpose actor; the closed
preparation actor and its intent/proof approval are not delivery permission.
Independent root controls must admit LIVE/checkpoint-zero before acquisition.
Neither missing local grants nor reconstructed outcome bytes establish the
private outcome store's state. This path does not select RECOVERY or store its
raw3; the separately authorized RECOVERY path below uses its existing distinct
policy family, not a switch or fallback inside this LIVE action.

The following guarded methods take the same exact completion/reconciliation,
target, work, current and remaining-capacity keywords as the preparation methods:

- `load_oidc_session_activation_completion_recovery_release_grants` returns
  `(acquisition_claim, grants)`, each an existing `ConsumeRecord` or `None`.
- `claim_oidc_session_activation_completion_recovery_release_grants_attempt`
  spends the target's acquisition slot before issuer contact.
- `append_oidc_session_activation_completion_recovery_release_grants` also takes
  `originals=(client_authorization, server_bootstrap)` and retains the first
  opaque raw2 before admission, under that exact work's successful new claim.

`release-grants-claimed` is an appended raw0 consume kind at index 17. All earlier
indices, encodings and domains are unchanged; `release-grants` still uses its
original index 14. The claim requires the retained proof. The recovered-prefix
extension now allows this exact grant stage, still without replacing original
SQL/completion/hints. An existing claim **or** existing grants prohibit new
acquisition and this public delivery attempt: lost issuer replies and uncertain
prior release cannot be repaired by another actor, new issuance or grant reuse.
Historical grant bytes without the new marker remain readable but are not
reusable authority. The preparation loader remains exactly tuple5.

After genuine raw2 admission, the separate
`claim_oidc_session_activation_completion_recovery_release_attempt` takes
`client_authorization_digest`, `request_identity`, `profile`,
`server_bootstrap_digest`, `expected_outcome_digest`, `work`, `current` and
optional `maximum_original_bytes`. It accepts only the source-fixed LIVE profile
and returns the authorization digest after normal durable publication. Its key
is the **same global client-authorization digest** as existing LIVE/recovery
dispatch claims, not a new namespace. Any existing claim refuses even identical
metadata. The caller makes this claim before the protected socket exchange.
No raw release request/response, old/new token or outcome is appended here.

The source holds eighteen possible consume files without widening global byte,
logical or physical ceilings. For example, activation7 plus consume18 needs25
files, which fits the existing `7*M + 10*C` ceiling at `M=3, C=1`; the recovery
scan ceiling is still `17*M`. A full or very small journal may refuse before an
effect rather than acquire more capacity. The extra raw0 has only its bounded
`MAX_RELEASE_GRANTS_CLAIM_BYTES`; all existing payload caps remain unchanged.

## Fresh retained-outcome RECOVERY persistence

The .214 guarded path requires a distinct fresh `retained-release`-purpose actor and
independently configured RECOVERY/checkpoint-one authority. It does not choose a
checkpoint from local absence, reconstruct proof that a private outcome exists,
or renew the original delivery expiry. This is not a retry or profile switch by
the LIVE action. The normal post-intent recovery APIs remain unchanged.

The custody client and journal expose:

- `load_oidc_session_activation_completion_recovery_retained_grants`
- `claim_oidc_session_activation_completion_recovery_retained_grant_attempt`
- `append_oidc_session_activation_completion_recovery_retained_grants`

Each takes keyword-only `finalization_digest`, `activation_authorization_digest`,
`release_intent_digest`, `issuer_policy_digest`, `completion_originals`,
`reconciliation_digest`, `work`, `current` and optional `maximum_original_bytes`.
Append additionally takes `originals=(client_authorization, server_bootstrap,
outcome_original)`. The four identifiers select the **same existing recovery
policy slot and filenames** as the normal post-intent methods. No new codec,
source-revision exception, per-policy namespace or retry marker is introduced.

The loader returns `None` if that policy has no claim, otherwise the existing
`RecoveryGrantRecords(claim, grants_or_None)` data shape. Required completion,
intent and proof history must still exist and agree before this absence return.
The journal reads the original completion/hints or exact separate reconciliation,
the activation/consume claims and retained intent/proof records. It checks their
immutable source/slot associations, exact raw6 equality and the actual framed
intent identity; it admits setup metadata without reading the setup body.
The caller performs genuine signature, proof, root-policy and checkpoint
admission. Stored DATA, including the outcome original, is not private-store
existence evidence or permission to release.

The claim is durable **before issuer contact**. Old and new acquisition APIs
collide on the same slot: every existing/recovered same-policy claim prohibits
another acquisition. New guarded append requires this exact work's successful
claim and original reconciliation/intent association; neither a recovered claim
nor the normal API's in-memory claim can enter that continuation. Only work and
bounded locator identities are retained in memory, never raw6 or a token. The
append latch is removed after successful publication and is never recovered.

Opaque raw3 is retained before the caller's semantic admission in this new path.
The unchanged codec bounds the three frames at 16 KiB, 16 MiB and 64 KiB. Malformed
or uncertain replies do not authorize recontact; a claim without its retained
reply remains terminal. The older normal post-intent path still retains only
its already-admitted triple. Neither path replaces original completion/hints.

After genuine grant admission,
`claim_oidc_session_activation_completion_recovery_retained_release_attempt`
takes the same five scalar fields, work/current and capacity keyword as the
LIVE dispatch method, but accepts only `release_attempts.RECOVERY_PROFILE`.
It shares the **global client-authorization slot**, record codec and native
publication implementation with LIVE and existing recovery dispatch claims.
Any existing claim refuses, including identical metadata. It returns the
authorization digest only after guarded durable publication, before the
protected socket exchange; no request, response token or cookie is journaled.

## Original allowance and native publication

`maximum_original_bytes` is an exact integer remaining representation allowance
from zero through 64 MiB; `None` retains that upper ceiling. Before the first
selected body read, every operation reserves three times the actual selected
encoded lengths, three times any new encoded publication length, and 16 KiB of
metadata. The source exports `COMPLETION_RECOVERY_METADATA_BYTES` and the pure
`_completion_recovery_publication_bytes(kind, originals)` upper-bound helper.
The helper covers publication only, not the selected history. Callers must
reserve their already held graphs and originals separately within the same
overall allowance. Large otherwise valid originals can therefore fail closed.
The new retained-grant operations use the same preflight rule before body one:
three times the actual selected encoded history and any existing claim/raw3,
plus three times the new encoded publication upper bound and 16 KiB metadata.
The new publication upper bound is `MAX_CLAIM_BYTES` for a claim, or
`MAX_CLAIM_BYTES + 24 + sum(len(raw) for raw in originals)` for raw3, using the
unchanged recovery codec. Shape and frame bounds are checked before encoding.
The caller's tighter 2 MiB per-operation lane may reject otherwise valid history
or replies; it creates no additional allowance. All original/capture and future
work reservations still compose inside the original aggregate ceiling.

The global LIVE and RECOVERY dispatch claims independently require their fixed
`release_attempts.MAX_CLAIM_IO_BYTES` plus the same metadata reservation; it
is charged by the method itself. The LIVE grant loader also reserves selected preparation
records plus the optional acquisition claim/raw2 before its first body read.

The original cumulative work is charged directly before reads and publication;
callers must not wrap the charging method in a stable native callback or charge
the same I/O twice. `current` must retain original owner/actor resource ancestry
without recursively selecting records or taking the same journal lock. Missing
required history, a spent claim, or insufficient capacity refuses without
creating an operation. Corruption and changed immutable files poison the owner.

Publication reuses the source-private completion native transition owner: exact
temporary/final names, actual newly created descriptor/inode, private mode,
size, rename, fsync and normal close. It validates the known metadata inventory
and only then updates the expected directory stamp before the full original
guard. Three bounded streaming metadata scans are precharged from the admitted
file count; they read no prefix bodies. The closed inode identity must match
before readback is installed. There is no generic readiness bypass, arbitrary
descriptor exemption, widened quota or retry after an uncertain publication.

This is source-only integration, unbuilt and unexecuted. The byte reservations
are not a heap/RSS guarantee; filesystem durability still depends on native
fsync semantics and provides no independent anti-rollback anchor. Independent
release-profile/checkpoint admission and protected token/cookie continuation
remain requirements of the actual caller, not facts established by these
records. Missing local intent/outcome does not prove either
private outcome existence or non-execution, and no SQL retry or delivery-expiry
renewal is authorized.
