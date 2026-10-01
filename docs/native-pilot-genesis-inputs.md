# Cold-start candidate input composition

[Back to the lifecycle](native-pilot-lifecycle.md)

The cold input compiler fills the existing **66-job** sequence from actual
executor observations, earlier input/result originals and explicitly selected
public configuration. It produces candidates for the independent decision
service; it is not that service and does not approve its own output.

## Retained dialogue

`native_pilot_genesis_inputs.compose()` accepts:

- The literal current JobRequest/v2 and its independently retained hash.
- The original Execution/v2 configuration and hash, original boot identity and
  current BOOTTIME/UNIX samples.
- The exact completed job prefix: each earlier candidate input paired with its
  actual returned result. The current frame's `previousResult` must match the
  immediate predecessor byte for byte and by hash.
- The accumulated observations **before** the current frame, plus the closed
  public selection fragment for this job.

The request contains only an observation **delta**, not the full transcript.
The compiler checks the exact source-defined observation timing, rejects future,
missing or rebound observations, then returns the new accumulated snapshot.
Accumulated observations must also match their producing owner's retained
result hashes or direct result bytes. It never predicts a PID, signed result,
activation descriptor or future grant. The compiler transcript has a 128 MiB
cap; the executor independently enforces its fuller retained-byte budget,
including approvals and public-result copies.

The result has five fields: `inputOriginal` (bytes), `inputSha256`, `deadline`,
`epochLimit`, and `observations`. Bounds intersect the original execution,
current request and current producer. They do not replace the actual executor's
retained, possibly tighter historical limits. An expired input is rejected,
not regenerated with a new lifetime.

The independent provider must retain its dialogue, authorize the exact candidate
and use the existing protected input/approval installation and transport. Calling
the compiler twice is not permission to execute twice. Parsing caller-supplied
bytes alone does not authenticate that caller or prove an observation is live.

## What remains independently selected

`selection_fields(job_name)` exposes the exact source-fixed fields; it does not
accept a custom job list, callback, template or substitution language. Unexpected
fields are rejected. Original documents are ASCII strings inside these fragments.

| Existing job family | Independently selected fragment | Derived from actual predecessors/observations |
| --- | --- | --- |
| Closure set | Three approved member manifests | Existing cold-bootstrap preparation format |
| Assignment | Trust original and native assignment payload, without closure-set roots | Actual preceding closure-set original and roots |
| Cold binding | Commissioning ID, initial revision, original window | Literal signed assignment, its selected trust and closure set |
| Parent precreation | Parent and delivery configuration originals | Original execution window and configuration/key hashes |
| Parent start | Controller executable hash | Actual precreation and configuration hashes |
| Ordinary/endpoints preparation | Ordinary launch or endpoint configuration original | Original window, parent pins and controller hash |
| Initial checkpoint | Delivery configuration, endpoint role, counters, authority keys, checkpoint policy | Actual parent/service identities and initial-state commitments |
| Initial anchors/history | Empty fragment | Exact checkpoint input and actual checkpoint/anchor signatures |
| First ordinary runtime | Runtime policy and peer label/configuration expectations | Observed process, cgroup, executable and directory identities; authenticated UID/GID |
| Second runtime/ordinary delivery | Empty fragment | Shared runtime inputs; delivery reuses its runtime input byte for byte |
| Ordinary grant | Initial transition-head hash | Actual deliveries and native service grants |
| Native delivery | Credential descriptors and endpoint configuration, or coordinator image pin | Actual runtime, activation, original window and fixed destinations |
| Native role keys/admission | Existing key policy; admission has an empty fragment | Actual cold binding, delivery and role-key authorization |
| Native closure/transport/service grants | Existing explicit time limits and, as applicable, supplied ciphertext/transport or verifier port | Actual authenticated key pairs, histories and retrieval-store observation |
| Native launch | Trusted-time settings and trust path | Actual authorized originals, hashes and fixed installation paths |
| Coordinator assembly | Five peers' independent label/configuration expectations | Observed process identities, authenticated grant UID/GID and four exact source pins |
| Store initialization | Empty fragment | Literal proof scope from the actual cold-binding result |
| Native installation | Empty fragment | Exact preceding launch input and bundle, checked by the existing installation planner |
| Parent/endpoint release | Empty fragment | Actual launch bundles, closures and observed configuration/precreation |
| Other fixed owner actions | Empty fragment | Existing action selector; public installations also validate their actual predecessor plan |

No keys, signatures, ciphertext, policies, approvals or successful owner receipts
are manufactured. Public candidate composition performs no file/network access,
installation, process launch, signing or resource cleanup. The real owners and
native receivers remain responsible for those operations.

## Remaining integration and verification

This closes candidate composition for the cold catalogue, not the independent
decision service, adopted176 composition, protected runtime installation or an
end-to-end pilot. The complete lifecycle still needs approved same-source
packages, external services and a demonstrated application allow/deny flow.

Focused controls use deterministic synthetic signed originals and the existing
public validators. Unconsumed fixture positions are explicitly labelled padding,
not successful owner results. They cannot establish a live protected ceremony,
hardware custody, actual provider traffic or production acceptance. Verification
results for this batch are recorded in [production progress](production-status.md).

The initial `7143a956` run exposed activation arrays being passed to an
object-only decoder. Corrected `a514b269` reuses the existing bounded canonical
list parser and passes all **39 controls in the three affected suites** in
**28.753 seconds**; **63 unaffected controls** passed in the initial run and were
not repeated. Nine Python files pass grammar/both Make inventories and five
modules import from the archived source. This accounts for 102 distinct focused
controls, not a final-tree full-suite rerun. No native/runtime rebuild or cloud
execution was performed.
