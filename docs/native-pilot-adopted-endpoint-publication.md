# Operational endpoint publication

The `.419` connection lets the existing operational `endpoint-inputs` job
publish the four public originals its runtime consumes. It does not introduce
a new job, approval protocol, signer or custody owner. Publication follows the
existing independent Approval2 and complete input validation.

## What is published

All destinations are fixed beneath `/etc/serverware/native-pilot-inputs/`:

| Original | Source and checks |
| --- | --- |
| `endpoint-peer.json` | Common peer from all five installed ordinary runtimes, joined to retained bootstrap/cohort process and executable observations. Independently selected security-label and configuration expectations remain unchanged. |
| `endpoint-proof-scope.json` | Literal measured scope already bound into the approved adoption input. |
| `endpoint-retrieval-manifest.json` | Exact empty fresh-ledger manifest derived from that scope; no invented receipts or objects. |
| `endpoint-assignment.json` | Literal signed assignment from the approved adoption input, joined to the proof scope. |

The compiler still returns candidate bytes only. The plan checks the selected
fixed destinations and exact hashes; only the actual authority executor performs
filesystem publication. A matching hash alone is not installation evidence.

## Publication and retained ownership

Before changing any file or mode, the executor validates the complete plan,
opens the exact previously installed cold originals and adoption authorization,
and checks that all four publication destinations are absent. The selected
object directory must already exist, be empty and root:root0700, and have
protected ancestors. It must not be the received core's directory.

The existing fresh-store installer freezes that same directory to 0555. The
executor retains its actual descriptors and identity, publishes each original
exclusively using the existing publisher, and reads back the exact approved
bytes. Retained checks continue through subsequent phases. Descriptors close
only after the actual conductor's cleanup is known complete.

An error consumes the attempt and preserves partial files and directory mode.
There is no replacement, retry, repair, deletion, directory creation or deadline
renewal in this job. Interrupted acquisition or uncertain cleanup must not be
reported as a successful publication.

## Custody is not reinitialized

The empty directory is the operational retrieval auxiliary store. It does not
replace the transferred durable core, its existing receipts or publication
history. `PilotEndpointInputs.prepare_adopted()` still requires the genuine
received core, and native adoption still uses the real transferred descriptor.
No fresh-directory report is treated as custody, service readiness or approval.

## Explicit directory provisioning

The existing `scripts/prepare_native_pilot_resource_roots.py` helper provides
an opt-in `--profile adopted-operational` inventory. It extends `adopted-cold`
with `/var/lib/serverware/native-pilot-retrieval-objects`, an empty root:root0700
auxiliary directory. Without `--create`, it only inspects. With `--create`, it
creates missing fixed entries exclusively; it never repairs existing entries.

The original `legacy` and `adopted-cold` inventories are unchanged. The endpoint
selection must still explicitly name its independently approved directory;
the new profile does not rewrite that selection or prohibit another separately
provisioned protected directory. A frozen 0555 store is not a fresh 0700
provisioning target and must not be reset for a retry.

## Verification and remaining work

Frozen `c001c5d6` passes all **73 focused controls in seven suites in 7.415
seconds**, with no failures, errors, skips or corrective reruns. Ten changed
Python files pass grammar/both Make inventories, and six modules import.
The pass uses the existing pinned Python 3.11.15/vendor snapshot, one CPU,
isolated user/network namespaces and a 180-second outer timeout.

The six plan controls use real deterministic test signatures for synthetic
public associations. Their nested cold framing is intentionally **not** a
native-valid receipt chain. The eight filesystem controls run the actual
publisher, reader, empty-store installer and retained directory in bounded
child chroots: exact readback, preflight/no overwrite, missing/nonempty inputs,
core-directory alias refusal, retained mutations, a concurrent create and
uncertain close. Nineteen resource-root controls cover the explicit profile
and real FD-relative operations under a temporary test root. Catalogue checks
confirm 56/128 shared publication slots; actual-byte limits still independently
apply and not every combination of allowed individual maxima fits.

These are component checks, not a full approved lifecycle, actual cold-core
transfer, hardware custody or live application run. No host provisioning,
native/runtime rebuild or cloud/paid operation ran. Exact source and logs are
recorded in [production progress](production-status.md).

An independently operated approval provider, compatible approved runtime
packages, protected deployment and a real application credential-replacement
flow remain required. Source **36/46** and production acceptance **0/6** remain
unchanged.

The next source connection is a fixed peer-side caller for the existing
`ApprovalPeer` lifecycle transport. It must retain the actual 244-exchange
transcript, use the existing candidate compilers, and obtain the existing
protected approval originals from an independent decision authority. Neither a
successfully compiled candidate nor an unrelated application approval grants
commissioning authority; a new lifecycle protocol is not needed.
