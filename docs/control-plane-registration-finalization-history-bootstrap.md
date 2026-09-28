# Finalization history cold configuration

Signed parent v18 adds nullable `finalizationHistory`. Parents v2–v17 and v18
with a null lane remain finalization-history-disabled. A non-null lane requires
the genuine [registration history](control-plane-registration-history-bootstrap.md)
material and current finalization v4 configuration. The complete signed parent,
including both histories and every encoded enrollment, still has one 4 MiB cap.
Oversize originals fail; there is no new descriptor, private key or allowance.

The nested `serverware.controlPlaneRegistrationFinalizationHistory/v1` object
contains exactly `schema` and `finalizations`. Each sorted, unique member contains
`configurationDigest`, `plannerAttestationReceiptDigest` and
`registrationFinalization`, the existing exact nested v4 scope. It has no root,
package, cohort or archive field. Its selectors resolve only against the already
authenticated registration archive and its independently configured operation
scopes. No second catalog or self-appointed historical trust root is introduced.

Cold admission obtains the genuine selected configuration/generation/cohort and
the exact archived root from that shared material. It verifies original
finalization caller, grant and state enrollment signatures using the existing
v4 bootstrap admission, including the configured transition purpose, generation,
key exclusions, predecessor/pending succession and capacity. The genuine archived
registration caller public key is retained by registration history solely to
preserve caller-key separation. Finalization pending state, completion packet
digest and original authorization digest are independent signed configuration
pins, never values adopted from returned or retained result data.

`_FinalizationHistoryMaterial` has six immutable fields: `archive`,
`registration_history`, `scopes`, `valid_from_epoch_ns`, `valid_until_epoch_ns` and
canonical `original_bytes`. The first two reference the same actual parent
registration-history material and archive; there is no copied trust catalog.
Its current interval is exactly the archive/current-provenance/startup-receipt
intersection already admitted for registration history. Startup rechecks both
histories before private-key intake. `_produce_v18_on_work` requires explicit
history current interval and epoch and performs the same nested admission before
root signing; producing an original does not provision production authority.

Each `_FinalizationHistoryScope` retains the selected configuration/generation/
planner-receipt identifiers, unchanged original interval, shared archived root,
three immutable enrollment originals, independent pending tuple, completion
packet/authorization digests and canonical scope bytes. `_scope_on_work` requires
the actual shared material and matches the exact snapshot and registration scope,
including the same root object. This returns configured data, not successful
historical replay or fresh action permission.

Request consumers must authenticate original finalization controls, resolve the
genuine planner context through the archive and replay all original signatures,
intervals and operation bindings under the current request work/window. Nested
registration evidence uses its own configured historical operation scope. Cold
endpoint/FD fields are validated data, not opened or substituted for the current
transport. No expired control becomes a current clock or execution permission.

The canonical nested originals and exact selected enrollment lengths support
aggregate reservation before retained body reads. Admission charges capture,
lookup and enrollment work on the original ledger; its conservative copy reserve
does not claim a process-heap bound. This slice supports configuration/key changes
only within the existing supported-source contract. Unknown old source remains
rejected; activation history and explicit older-source adapters remain separate.
This is source-only, unbuilt and unexecuted, with no provisioning or production
acceptance evidence.
