# Explicit recovery of an unchanged private release

`authority_oidc_session_activation_release_recovery.OidcSessionActivationReleaseRecovery`
connects a fresh [recovery-only root authorization](oidc-session-activation-release-recovery-authorization.md)
to the existing exact outcome and original encrypted delivery. It returns only
the unchanged raw 64-byte token to its private caller. This is source-only,
unbuilt and unexecuted; it is not a transport acknowledgment or a deployed flow.

## Separate present permission from historical evidence

The constructor requires original `recovery_authorization_bytes` and
`custody_bytes`, the actual `root_public_key`, independently supplied
`expected_scope`, the actual `delivery_custody_key`, an actual `outcome_store`,
and one current `live_window`, positive `transport_deadline_ns` and cumulative
`work`. The fixed isolated process remains UID/GID 65502 with no supplemental
groups. No history or private signing key enters this owner.

The fresh authorization has a distinct recovery purpose. Its closed scope pins
configuration, database, generation, runtime, receiver, caller, old custody
identity, delivery-key digest, delivery ID, exact outcome digest and directory
identity. Those expectations must come from independent authority, not a local
file scan or the outcome being recovered. The owner genuinely reauthenticates
the original grant and its scope on construction and every recovery call.

The old [release custody](oidc-session-activation-release-custody.md) is verified
through a separate historical entrypoint: exact root signature, original
schema/purpose/source, planner/key provenance and target bindings remain
mandatory. Its old outer interval may have expired, but no live custody grant
is renewed. The actual key digest must match both historical custody and fresh
recovery authority. Database and role-key provenance come from genuine original
state enrollment. The ordinary material returned by historical admission is
not accepted from the caller as permission.

The old intent and proof likewise use distinct historical admission paths.
Their original signatures, root enrollments, key separation, targets, signed
interval relationships and current old-token possession are checked. Historical
evidence does not bypass actual current processing bounds or delivery expiry.
Existing live verifiers retain their freshness rules. Recovery remains within
the same admitted source/configuration/generation; this does not implement the
separate cross-generation historical-authority milestone.

## Existing outcome only

The supplied [outcome store](oidc-session-activation-release-outcome-store.md)
must already have completed its own cold admission under a separate genuine
root storage grant. Recovery compares its sealed scope to the fresh recovery
scope, including the same directory and exactly:

```text
checkpoint.recordCount = 1
checkpoint.outcomeDigest = recovery authorization's outcomeDigest
```

Checkpoint zero is rejected even if that handle subsequently appended a record.
A cold handle admitted at checkpoint one has already recovered the exact
record, with a normal-close read and synchronization. Recovery does not create a
directory or append a missing outcome. Root key identity and immutable owner
configuration are also joined; a root storage grant alone is not release
permission or an independent latest-state witness.

`recover_on_work` consumes exact original `record_bytes`, `proof_bytes`,
`proof_enrollment_bytes`, `intent_bytes`, `intent_enrollment_bytes`,
`old_token_bytes` and `envelope_bytes`, plus the current allowance. All originals
are bounded before native admission. The canonical record must match the
independently authorized outcome digest, caller, scope and original custody.
Its consume/receipt/producer commitments are authenticated by the original
intent and proof. A record reconstructed from those actual admissions must be
byte-identical to the retained original; no newer grant or intent changes it.

The actual root-pinned 100-byte ciphertext and delivery scope feed the existing
live AEAD path. Genuine `retain_on_work` calls before and after opening perform
unchanged-record readbacks, not cached success. Because checkpoint-one admission
is mandatory, neither call may take the store's first-publication path. The
same exact token is held locally until the second normal-close readback and all
final guards succeed. No token is generated, resealed or saved in the journal.

## Lifetime and failure behavior

Construction and calls keep the identical cumulative work object and original
three-sample clock bracket. Supplied ceilings and deadlines are intersected with
the owner's already narrowed limits, never used to restart them. The store
independently enforces that same work and bracket. Fresh recovery authority,
historical evidence, custody configuration and live delivery guards remain
joined through private return, including sticky inner clock observations.

After ownership is established, a construction or locked recovery failure closes
the recovery owner and outcome store without deleting, replacing or retrying
anything. An uncertain visible record remains evidence, not permission to repeat
consumption. A later authorized attempt needs separately admitted fresh owners;
expired old execution permission is never extended. Python byte objects cannot
be guaranteed erased from memory.

This component contains no consume SQL, provider call, new outcome, automatic
retry, public dispatch, browser/session success claim or off-host rollback
assurance. Cold resource delivery, the finite private worker, authenticated
transport/response handoff, public permission and portal recovery remain
separate work. A private token return does not prove that a network recipient
received it exactly once.
