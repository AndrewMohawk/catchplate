# Cold publication commissioning

**Legacy integration blocker:** the cold v1 coordinator's immutable runtime
hash depends on the assignment that commits that same runtime through its
closure set. This profile cannot be commissioned coherently. The explicit
[bootstrap/late-runtime successor](native-pilot-genesis-bootstrap.md) is integrated
in source and passes its focused compiler check; the acyclic stored core
does not remove this separate configuration cycle. See the
[confirmed dependency analysis](native-pilot-publication-commissioning.md#remaining-integration).

The ordinary publication bridge requires an authentic prior receipt. It cannot
also be the producer of its own first receipt. Cold commissioning therefore has
a separate, purpose-fixed runtime and generation-independent authorization.
It does not admit a policy, install a generation, or authorize application work.

## Receipt-first sequence

```mermaid
sequenceDiagram
    participant C as Cold coordinator
    participant D as Durable recovery store
    participant N as Native publication signer
    participant R as Immutable retrieval store
    participant W as Independent current-signature witness
    C->>D: Initialize the exact approved commissioning scope
    D->>D: Persist typed initial state; fsync and read back
    D-->>C: Signed evidence of that durable genesis
    C->>N: Prepare initial publication from that evidence
    N-->>C: Signed acyclic core; no final receipt yet
    C->>R: Store the exact core
    R-->>C: Signed immutable storage and fs-verity evidence
    C->>N: Complete using that actual stored core
    N-->>C: Literal Uninstalled receipt and signed completion
    C->>D: Finalize the exact receipt
    D-->>C: Durable finalization witness
    C->>W: Mirror the completion and durable witness
    W-->>C: Independently durable witness
    C-->>C: Verify all originals before releasing the bundle
    Note over C,W: Policy loading is a later, separately authorized step
```

Initial ledger and spool roots are domain-separated hashes of the persisted
typed initial state and its approved scope. Callers cannot supply replacement
roots. `Uninstalled` has no predecessor, committed or published generation,
prepared publication, or allocated ingress range; its ledger ordinal is zero.
A positive initial publication revision is explicitly approved. Directory
emptiness and retrieval-store ownership metadata are not policy-state evidence.

The core excludes its storage references and final receipt signature. Retrieval
first persists that core and signs the actual stored object; only afterward
does the native signer construct a receipt referring to it. The independently
approved native grant pins the retrieval key and guest, the retrieval grant
pins the native grant, and later ordinary grants pin both exact grant digests.
This ordering avoids hashes that depend on their own future results.

## Admission and ownership

Cold scope binds one commissioning identity, assignment, proof scope, namespace,
boot/time namespace and original lifetime. It deliberately excludes a future
policy generation, signed load, driver-generation receipt or prior publication
receipt. Each actual owner checks its separately approved scope and keys.
Ordinary services retain full root-authenticated history admission; the native
grant independently selects the exact DRS/CSA epochs and public keys.

The coordinator has only two ordinary sessions and two inspected native
endpoints. It cannot borrow the normal bridge's permissions or manufacture a
normal dispatch request. Its actual parent, peers, PIDFDs, fixed socket paths
and original deadlines remain checked during transport. The final handoff is
the verified exact bundle, not permission to install or proof of a running
application. An acknowledgment only confirms receipt of that handoff.

The cold measured closure is a separate explicitly selected three-member
profile: retrieval, publication signer and coordinator. It must not relabel
the signer as an ordinary bridge or expand the old measured closure inventory.
The ordinary cold runtime is likewise separate from the operational publication
runtime; it forbids generation admission and accepts only commissioning
commands. Requiring the normal driver-generation grant here would recreate the
startup cycle. Its separately selected initial-history/state v2 covers the two
DRS directories and one CSA directory; old history/runtime profiles stay closed.
An operational empty journal cannot establish cold genesis.

The two-ended result socket is part of the signed cold activation inventory.
The actual launch parent retains the final parent-only descriptor; it is not
forwarded to the child, and child descriptors are not renumbered. The parent
checks the actual sender and independently verifies the full grant/history/
bundle before retaining it and acknowledging its exact hash. The cold-only
parent API returns owned bundle bytes while retaining its real process/reaper
owner; the caller must still close it through bounded cleanup. Normal process
exit behavior, stdout and installation paths are unchanged.

The parent keeps servicing inspections after sending the acknowledgment. It
releases the retained bundle only after replying to a distinct, one-use
inspection proving that the child received the exact handoff acknowledgment.
Actual child identity and the original scope are rechecked after both writes
and before release. This is not a child-exit or cleanup success claim.

## Remaining integration and verification

The connected native producer and retained handoff pass the focused assembled
compiler check below. Six pure signature/format controls are authored, not
test-compiled or executed. No successful runtime execution is
claimed. A separately selected [operational adoption](native-pilot-adoption.md)
now connects those context changes in source while preserving the literal
receipt and roots and passes its focused compiler check. Runtime verification
and commissioning remain open;
the legacy Published/Commit-only baseline remains closed.
Full commissioning/package producers, actual retained handoff consumption,
uncertain/restart recovery, the remaining signer families, independent service
provisioning and connected application acceptance are still required.

The adoption contract independently approves the exact cold bundle
and prior authority context together with the actual current assignment,
configuration and proof scope, without future load/grant hashes. Only that
literal baseline may use prior keys and proof scope; new receipts must use
current authority. Shared admission, native and ordinary grants, Retrieval,
Persistence and the gate-side receipt verifier must all use the same durable
one-use mapping. Existing load-to-receipt/root equality stays unchanged. Original
lifetimes intersect; neither re-signing the baseline nor resurrecting expired
authority is a recovery mechanism.

The old graph's 164 jobs and 113 selectors do not count these cold ceremonies.
Source checkpoints remain 36/46 and independent production acceptance remains
0/6. No cloud or paid work is authorized by this source change.

## Verification

Exact source `d6443f6c2cf6685829cd4663330db9aabec5affb` passes
`cargo check --offline --locked --frozen -j1 --bin catchplate-decision-gate`
under the pinned Rust 1.88 image, with one CPU, 8 GiB memory and no network.
Cargo reports 1 minute 5 seconds, with 312 library and 2,496 binary warnings
including duplicates. This is a compilation check, not a release build or
execution of the six authored Rust controls.

The initial `87a8d460` attempt stopped before compilation because the pinned
image was absent. The exact image was restored, and source review corrected
the post-ACK inspection and post-write expiry checks before the assembled run.
No compiler errors occurred in that run. Both source archives, the missing-image
result, image-pull log, exact harness and compiler logs are retained at
`codex-offload/catchplate/engineering-builds/d6443f6c-genesis-FcAp86/`.

Five documents pass 437 local file targets; anchors and external links are not
checked. Actual native guests, journals, immutable stores, parent handoff and
cleanup have not been executed for this slice. No application, provider, cloud
or paid test ran. These results do not advance independent production gates.
