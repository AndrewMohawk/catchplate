# Witness journal durability and recovery

Status: source implementation and read-only review only, unbuilt and unexecuted.
This is a repair of the existing replay witness's local record durability, not
an independent initialization-decision service, rollback-resistant storage or
permission to start the currently blocked authority runtime.

## Ambiguous publication

The existing witness persists an immutable record by completely writing a
private temporary file, changing it to mode 0400, synchronizing the file,
renaming it without replacement and synchronizing the parent directory. Only
then may it publish the stored exact response. A visible filename is not a
successful durability acknowledgement.

Source review found a recovery gap: a successful rename followed by a failed
directory sync leaves a visible record, but the old startup scan synchronized
the directory only when removing a temporary file. A restarted witness could
therefore accept and replay that record without completing the failed barrier.
It also lacked an explicit failed-handle state covering every replay branch.

The guard-free `authority_witness_journal.py` component owns the I/O health
state and shared serialization lock. A new handle is not ready. Recovery runs
the witness's existing validation scan and then unconditionally synchronizes
the directory before becoming ready. The scan's validated directory identity
and change stamp must still match immediately before and after that barrier;
the helper must not silently adopt a later stamp. A recovery error leaves that
handle unusable; callers must create a new handle and revalidate storage, not reset a
boolean and continue with partially reconstructed indexes.

Publication retains the existing file names, bytes, bounded full-write loop,
mode, no-follow/exclusive creation and no-replace rename discipline. Any
ambiguous publication failure poisons the handle. Published records are never
removed as rollback. A later successful recovery may admit their exact retained
response only after the original record/chain/signature checks and a successful
directory barrier. A failed barrier yields no response acknowledgement.

The production witness uses the same serialization lock and readiness gate for
all transition/replay branches, including after request validation outside the
lock. Failure while updating the in-memory indexes after durable publication
also poisons the handle. A previously validated concurrent request cannot
bypass the failed state through an existing-response shortcut.

The helper borrows the directory descriptor; it does not provision, close or
transfer ownership of that descriptor. The existing measured launch binding,
singleton flock, signed quotas, record verification and generation/high-water
checks remain the witness's responsibility. No wire schema, signature purpose,
permitted phase, generation contract, runtime grant or launch role is expanded.
The new module must enter the measured source/import closure at preparation;
an old launch manifest does not authorize the changed code.

Directory metadata comparisons supplement the existing singleton/ownership
premise; they are not proof of exclusion against arbitrary privileged writers,
nor do timestamps establish an independent monotonic head.

## Verification boundary

The authored `test_authority_witness_journal.py` fixtures exercise real local
files and the shared production I/O helper with deterministic injected I/O
failures. They also inspect the production linkage. They do not bypass the
launch guard or import an altered transition registry to claim witness startup.
They are local component controls, not a power-loss experiment, a fully
launched witness service or a statement about a provisioned filesystem's
durability guarantees. No test has run. The isolated lane remains subject to
the exact source freeze, approved controller/dependency closure and sequential
no-build workflow in `goal.md`.

## Remaining storage and initialization requirements

This repair deliberately does not claim to solve separate source gaps:

- The signed startup minimum sequence/digest is a floor, not an independently
  retained latest head. A valid suffix rollback above that floor still needs
  independent detection. Local fsync, signatures and contiguous history do not
  provide that external authority.
- The [completion-capacity accounting](authority-witness-capacity.md) now holds
  one maximum-sized terminal record and slot per open existing reservation,
  reconstructs those holds at recovery, and rejects generation activation while
  work remains open. This is source-only logical quota, not filesystem allocation
  or an initialization service's complete materialization/recovery reservation.
- The generation drain guard does not transfer outstanding reservations.
  Initialization generation handover must preserve the consumed identity and
  pending decisions explicitly; historical unresolved cross-generation state
  requires separately admitted repair rather than automatic activation.
- The existing witness has a closed local role, Unix peer/deadline assumptions
  and `networkAllowed: false` state binding. It is not a remotely operated
  initialization service merely because its append machinery is reusable.

The separate [initialization decision protocol requirements](authority-audit-initialization-decision.md)
describe the missing external state and SQL ordering. No implementation or
provisioning of that service is implied by this durability correction.
