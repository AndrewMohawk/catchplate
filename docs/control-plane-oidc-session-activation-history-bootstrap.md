# Activation history cold configuration

Signed parent v19 adds nullable `activationHistory`. Older v2–v18 and null lanes
remain disabled. Parent v20 additionally accepts activation-history v2; v19
remains v1-only, and a v1 inventory still carries no historical completion pins.
A non-null inventory requires the actual registration and
finalization history materials and shares their one authenticated archive and
historical root objects. No new catalog, key source, live descriptor lane or
execution permission is implied. The complete parent, all histories and encoded
enrollments still fit one 4 MiB maximum; oversize input is refused.

`serverware.controlPlaneOidcSessionActivationHistory/v1` has exactly `schema`
and `activations`. Each sorted unique entry has `configurationDigest`,
`plannerAttestationReceiptDigest`, `activationExecution`, `activationPlanning`,
`consumeExecution` and `releaseIntent`. Its child shapes are the existing
activation v4, planning v1, consume v4 and intent v1. No root or archive is
accepted in this new entry. Selection requires matching independently admitted
registration and finalization scopes in the shared archive.

`serverware.controlPlaneOidcSessionActivationHistory/v2` preserves that inventory
and adds exactly nullable `completionRecovery` to every entry. A non-null value
uses the existing closed completion-recovery v1 shape, with distinct optional
activation/consume lanes. Each lane independently pins `packetDigest`,
`authorizationDigest` and the complete `currentPending` tuple. Genuine cold
admission re-admits the entry's original caller/grant/state enrollments under its
archived root/configuration/generation; pending sequence and fence must join the
original execution predecessor. Consume requires the actual hints-enabled
execution and the same state enrollment as activation. These pins are not
inferred from retained response data or from absence of a journal record.

The nested endpoint must match the original execution endpoint for historical
provenance only. It never grants current contact. A fresh completion actor must
combine these independently signed historical packet/authorization/pending pins
with the separately enabled **current** completion endpoint, then genuinely
replay the selected originals before any completion-only exchange. Neither a
missing v1/v2 lane nor an unknown archived selector falls back to current pins.

Actual activation/consume enrollment admission binds archived configuration,
generation, dedicated caller/planner keys, common state enrollment and configured
key exclusions. Finalization history additionally retains its genuinely admitted
caller public key solely for these exclusions. The release-intent enrollment is
authenticated against its independently configured scope and all original key
exclusions, including the archived registration/finalization callers.

Two explicit historical-only cold helpers reuse the existing genuine
`planner._verify_historical_on_work`. Planning returns the existing immutable
planning material plus the unchanged original planner interval; the entire
planner interval must fit the selected archive snapshot. Intent cold admission
repeats historical planner verification before scope/enrollment joins. Neither
helper calls live freshness on an old interval, substitutes an old timestamp for
the current clock, or weakens ordinary `_admit_on_work`: its existing live
planner verifier and launch freshness remain unchanged.

Startup supplies `_history_live_window` and `_history_transport_deadline_ns`
from one actual current window on its existing work, in addition to the existing
receipt interval and epoch. The new admission only narrows that window to the
current archive authorization and preserves real epoch/monotonic floors through
nested verification. Historical snapshot intervals remain separate original
evidence. Startup rechecks the same window and shared material identities before
private-key intake. `_produce_v19_on_work` requires explicit current history
window/deadline and genuine nested admission, then rechecks current bounds around
root pairing, signing and final output. `_produce_v20_on_work` has the same
explicit original inputs and current-history arguments, admits v1/v2 through
the shared material constructor, and signs the distinct v20 envelope only after
that admission. Both retain the combined 4 MiB output ceiling and same work and
processing window. Neither provisions a completion or release service.

The actual FD entrypoint now projects the closed v2–v20 parent envelopes and
payloads, including the v17 registration, v18 finalization and v19/v20 activation
history data namespaces. Its v19 gate accepts history v1 only; v20 accepts
history v1/v2. This is a startup data-gate correction, not historical admission:
the unchanged sealed originals still reach genuine signed-parent/archive
admission. Historical descriptor numbers add no current key or purpose slots.

`_ActivationHistoryMaterial` has seven fields: `archive`, `registration_history`,
`finalization_history`, `scopes`, current `valid_from_epoch_ns`/
`valid_until_epoch_ns`, and canonical `original_bytes`. Each scope retains exact
configuration/generation/planner-receipt identifiers, original snapshot interval,
shared root, four genuine immutable cold child materials, original
`planner_attestation_interval`, canonical scope bytes and appended
`completion_recovery` (the exact immutable existing completion material, or
`None`). Original snapshot intervals are unchanged, not refreshed completion
authority. These remain configured data, not a successful original replay or
present caller grant.

`_lookup_execution_on_work` uses config/generation/authorization-enrollment
locators; `_lookup_intent_on_work` uses config/generation/intent-enrollment
locators. Both require a unique already admitted scope and reject absence or
ambiguity. Untrusted retained headers may select that key only: the consumer
must then authenticate the genuine original signature, original time and scope.
`_scope_on_work` joins the final authenticated archive snapshot to that same
configured scope/root. There is no fallback to current pins. Canonical cold
bytes and exact enrollment lengths remain available for aggregate reservation
before retained bodies, with no replacement allowance or heap-bound claim.

This is a supported-source historical target and completion-configuration
increment. The selected historical completion profiles support the actual
fresh-actor control replay and completion-only response path; they do not enable
activation SQL retry, fresh consume effects or protected release authority.
This does not complete all historical activation effect/release authority or
explicit older-source replay adapters. Unknown old source stays rejected. H05
remains partial; the source is unbuilt, unexecuted and unprovisioned, with no
production acceptance credit.
