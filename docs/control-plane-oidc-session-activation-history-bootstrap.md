# Activation history cold configuration

Signed parent v19 adds nullable `activationHistory`. Older v2–v18 and null lanes
remain disabled. A non-null inventory requires the actual registration and
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
root pairing, signing and final output. It does not provision a release service.

`_ActivationHistoryMaterial` has seven fields: `archive`, `registration_history`,
`finalization_history`, `scopes`, current `valid_from_epoch_ns`/
`valid_until_epoch_ns`, and canonical `original_bytes`. Each scope retains exact
configuration/generation/planner-receipt identifiers, original snapshot interval,
shared root, four genuine immutable cold child materials, original
`planner_attestation_interval` and canonical scope bytes. These remain configured
data, not a successful original replay or present caller grant.

`_lookup_execution_on_work` uses config/generation/authorization-enrollment
locators; `_lookup_intent_on_work` uses config/generation/intent-enrollment
locators. Both require a unique already admitted scope and reject absence or
ambiguity. Untrusted retained headers may select that key only: the consumer
must then authenticate the genuine original signature, original time and scope.
`_scope_on_work` joins the final authenticated archive snapshot to that same
configured scope/root. There is no fallback to current pins. Canonical cold
bytes and exact enrollment lengths remain available for aggregate reservation
before retained bodies, with no replacement allowance or heap-bound claim.

This is a supported-source historical target-admission increment. It does not
complete historical activation execution, completion/release authority or
explicit older-source replay adapters. Unknown old source stays rejected. H05
remains partial; the source is unbuilt, unexecuted and unprovisioned, with no
production acceptance credit.
