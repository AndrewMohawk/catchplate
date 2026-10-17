# Cold-to-operational publication adoption

Cold commissioning and normal operation have different measured closures,
assignments and proof scopes. A valid cold receipt cannot simply be treated as
if the current operational signer issued it. Re-signing it would also change
the exact receipt hash approved by the policy load.

This source slice connects an explicitly authorized adoption of that one
literal baseline. It does not deploy a pilot or grant authority to renew an
expired ceremony.

The [cold bootstrap successor](native-pilot-genesis-bootstrap.md) uses explicit
adoption Authorization/v2 and signature/v2, and requires coordinator Runtime/v2.
Legacy authorization/v1 remains paired only with runtime/v1. The keyless
validator likewise requires matching input/payload versions and emits the
corresponding result version; it does not sign or admit a live owner.

## One authorization, exact old and current contexts

The current assignment's independently selected supervisor signs an adoption
authorization containing the exact cold coordinator configuration, final
bundle, native and retrieval grant originals, and prior supervisor key. It also
binds the current assignment, production configuration, complete proof scope,
publication/retrieval keys and the two target ordinary histories and epochs.
The cold signatures, durable witnesses, literal receipt and original grant
windows are verified together. Both cold grants must agree on their original
checkpoint and revocation tuple.

The authorization deliberately excludes future policy-load, generation,
driver-generation and service-grant hashes. Operational grants refer to it,
not the reverse. The production configuration binding stays unchanged: the
separately authenticated late runtime carries the two ordinary grants. It is
not inserted into its own configuration hash.

All consumers retain the original cold BOOTTIME interval and both signed UNIX
grant intervals, intersected with the adoption/current-owner bounds. Current
trust and original receipt freshness still apply. An adoption is neither a
new historical owner nor permission to extend an old deadline.

## Durable and immutable ownership

DRS and CSA each write a unique adoption-prefix record into their actual
publication journal before processing their first operational command. The
record binds the authorization, cold bundle, literal baseline, current grant,
history/epoch, initial heads and actual owner fingerprint. Append, durability
and exact readback precede access. Recovery requires that exact prefix first;
conflicts, missing prefixes before operations and uncertain writes refuse.
An empty journal alone does not establish that adoption happened.

The operational retrieval owner receives a separate, read-only descriptor for
the actual cold immutable core. It checks the signed content and fs-verity
identity, cold file owner/mode, and genuine inherited descriptor identity,
then retains and rechecks that same file through responses. It does not
recreate the object at a new path or infer proof from directory ownership.

Only the byte-identical admitted baseline may use the prior signer and inner
proof scope. Shared publication admission, native publication, retrieval,
persistence, terminal verification and the gate's recovery verifier agree on
that exception. Proof queries still select the actual current outer scope and
current proof endpoints. New publication receipts and the Commit verifier use
current authority. Load-to-receipt and ledger/spool-root equality are unchanged.

## Explicit successors

| Consumer | Selected profile |
| --- | --- |
| Measured operational closure | Closure/assignment v5; twelve-member closure set v2 with a real publication signer |
| Ordinary DRS/CSA | Runtime v12; publication grant v2; initial-history/state v3 |
| Native publication | Launch v2; service assignment v2 |
| Native retrieval | Launch/grant v6; dedicated fifth cold-core descriptor |
| Native persistence | Launch v3; service assignment v4 |
| Operational bridge | Launch v10; RPC runtime v14; publication selection v2 |

The old eleven-member operational set and three-member cold set remain exact.
The new publication signer has its own fixed verifier path, not a bridge alias.
Legacy grants reject the adoption field. Successor-only authorization/grant
bounds are 2 MiB/3 MiB respectively; the bridge's whole-runtime 4 MiB bound is
unchanged, so oversized combinations still refuse. Historical caps remain in
place on legacy readers and inspectors.

## Verification and remaining work

Exact source `35f138c6fa82ee4336904e6912aa221364a9424c` passes
`cargo check --offline --locked --frozen -j1 --bin catchplate-decision-gate`
under pinned Rust 1.88, with one CPU, 8 GiB memory and no network. Cargo reports
1 minute 5 seconds, with 312 library and 2,469 binary warnings including
duplicates. The initial `b3786131` snapshot failed with one private-clock
visibility error. The correction uses the existing adoption accessor's actual
live-window validation, without exposing the raw clock or weakening a check.
Both archives and actual logs are preserved.

Five selected documents pass 438 local file targets; anchors and external links
are not checked. No Rust tests were compiled or executed. No runtime, native
guest, journal, fs-verity store, proof service, provider or cloud execution ran
for this slice. Repeated verification of the full bounded authorization is
currently conservative; its actual timing under original deadlines is unproven.
The archive, exact harness, compiler logs and checksums are retained at
`codex-offload/catchplate/engineering-builds/35f138c6-adoption-jiMkKv/`.

The [commissioning tools slice](native-pilot-publication-commissioning.md) adds
explicit static closure/assignment producers, a packaged entrypoint, retained
cold-result controller and native adoption validation. The authorization signer,
expanded commissioning graph, operational grant composition and independent
provisioning still need integration. Uncertain/restart recovery, later ownership/authority transitions,
remaining signer families and connected workload acceptance remain required.
This initial adoption is not a perpetual operational renewal path.

The old commissioning graph's 164 jobs and 113 selectors do not include these
expanded ceremonies. Source checkpoints remain 36/46; independent production
acceptance remains 0/6. No testable pilot or production completion is claimed.
