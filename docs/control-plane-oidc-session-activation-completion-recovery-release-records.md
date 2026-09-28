# Completion recovery preparation and LIVE release records

This source-only continuation stores DATA in the existing consume-family intent
and proof slots, followed by separately authorized LIVE grant acquisition and
dispatch records. It does not authenticate completion, sign an intent, request a
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
raw3; the existing separately authorized recovery family remains distinct.

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
The global LIVE dispatch claim independently requires its fixed
`release_attempts.MAX_CLAIM_IO_BYTES` plus the same metadata reservation; it
charges that work itself. The grant loader also reserves selected preparation
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
