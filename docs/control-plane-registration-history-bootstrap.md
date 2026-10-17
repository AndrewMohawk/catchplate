# Registration history cold configuration

Explicit signed parent v17 adds nullable `registrationHistory`. Older v2–v16
parents and v17 with `null` keep historical configuration selection disabled.
The complete parent remains limited to 4 MiB, including the encoded archive,
current provenance and all operation enrollment originals. This is not another
4 MiB allowance and does not provision keys, descriptors or a recovery service.

The nested `catchplate.controlPlaneRegistrationHistory/v1` object has exactly
`schema`, `currentEntry`, `archive` and `registrations`. `archive` is the existing
`{base64Url, byteCount}` original carrier. `currentEntry` has the existing
historical archive entry shape: actual artifact package/trust state, signed
configuration, configuration root, attestation cohort, exact configuration
digest and original validity interval. It is admitted by the existing archive
entry verifier, then its configuration, generation, cohort and root are joined
to the independently admitted current parent and runtime root. The control-plane
receipt interval alone is not authority-generation or cohort provenance.

The existing signed `authority_historical_archive` admission authenticates the
whole archive under the current independent root before any archived root is
retained. Its current authorization interval is intersected with the genuine
startup receipt interval. Startup supplies `_history_current_interval` and
`_history_now_epoch_ns`, then rechecks the resulting interval before private-key
intake. No original interval is renewed. `_produce_v17_on_work` requires explicit
`history_current_interval` and `history_now_epoch_ns` for the same genuine nested
admission before signing the parent.

Each sorted, unique `registrations` member has `configurationDigest`,
`plannerAttestationReceiptDigest` and `registrationExecution`. The latter is the
existing exact v3 registration execution scope, including caller/grant/state
enrollment originals and independent predecessor, current-pending and completion
packet pins. Existing execution bootstrap admission verifies those signatures,
configuration/generation/purpose and key separation against the selected archived
configuration/root; it also checks pending succession and enrolled capacity.
Historical transport and descriptor fields are validated cold data, not opened
or adopted as current effects. Current execution v3 must also be configured.

`owner._material.registration_history` is immutable
`_RegistrationHistoryMaterial`: the genuine archive, immutable operation scopes,
current `valid_from_epoch_ns`/`valid_until_epoch_ns`, and canonical `original_bytes`.
Each scope retains only its exact selector/interval, authenticated archived root,
three immutable enrollment originals, pending tuple, completion packet digest
and canonical scope bytes. These byte originals allow downstream reservation
before selecting or loading retained operation bodies; they are not success
objects or a claim of process heap usage.

The existing archive control lookup may use untrusted retained config/generation
and issue-time locators only to select an already admitted key. Genuine original
signature verification must follow. The final archive lookup uses the genuinely
verified planner receipt and original evaluation time; `_scope_on_work` selects
only its independently configured operation scope. It does not accept a record's
root or turn a lookup into successful historical execution. Historical replay
still verifies original control intervals and all original signer/execution
evidence under the current request's work and live processing bounds.

This source slice supports registration configuration/key history only under the
currently supported source contract. It adds no source-version bypass, renews no
execution authority, retries no SQL and grants no fresh actor permission. H05's
cross-source contract, finalization and activation history remain open. This
source is unbuilt and unexecuted; no deployment or production acceptance follows
from the configuration path.
