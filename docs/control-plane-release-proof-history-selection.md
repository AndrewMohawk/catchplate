# Fresh release proof over historical activation and consume evidence

This is source integration, not execution evidence. The current source has not
been built or run, and this path does not release a credential or establish a
browser session.

## Three independently authenticated contexts

| Context | Original authority | What it establishes |
| --- | --- | --- |
| Activation | R0 | The original activation caller, planner, target and delivery-key identity |
| Consume | R1 | The original consume caller, plan, state, packet and completion evidence |
| Fresh preparation | R2 | Current intent/proof signing, current configuration and fresh processing authority |

R0, R1 and R2 may be different roots and configurations. They are selected from
independently admitted cold originals, never accepted from a journal field or
inferred by trying another verification key. All contexts must describe the
same database and generation, with genuinely verified **complete state-enrollment
payload equality**. Re-signing unchanged state under another root is supported;
database, generation and state-role migration are not inferred.

Before a new human ceremony, the completion-recovery actor authenticates the
retained consume prefix under independently selected R1. The later complete
record read must match that prefix. Fresh `release-intent-proof` WebAuthn and
approval are separate from completion, consume and credential-release permission.
The original activation claim remains bound to R0.

## Explicit current-template bridge

The version-2 proof-input issuer policy and version-2 proof bootstrap carry the
wrapped exact `currentActivationPlanner` original. The version-2 control-plane
acquisition configuration pins that original to the currently admitted parent
planner. Version 1 retains its exact same-context schema and behavior; an old
profile is never silently upgraded or retried as version 2.

The current R2 planner is genuinely verified as a historical configuration
template. Its old activation launch window is not renewed. Present authority
comes from the distinct fresh policy, completion custody, intent and proof
intervals, all on the caller's original processing window and work ledger.

The existing release-custody v1 format remains unchanged. In the new bridge it
contains the exact R2 current planner, and the proof bootstrap checks byte
equality with its explicitly carried template. Its delivery-key digest must
also equal the genuinely authenticated original R0 planner's delivery-key
digest. **This is same-delivery-key continuity, not delivery-key migration.**

The actual proof worker uses R1 for committed consume evidence, state binding
and historical replay. It uses R2 for current custody, original fresh intent,
proof enrollment and proof signing. Its startup, dynamic delivery, producer and
control-plane receiver preserve that separation. A root-signed target alone is
not a successful packet, committed state or released token.

## Bounded and irreversible behavior

- Version-2 issuer policies have a 6 MiB per-original ceiling; enclosing parent,
  transport and cumulative limits may be smaller. No enclosing ceiling is raised.
- The separately held current planner, wrapped policy and actual public graphs
  count toward the existing 64 MiB cumulative original inventory. Future captures
  are reserved before the first selected record body, then carried forward once.
- Existing global intent/proof attempt slots remain one-use. A spent claim with
  missing output does not permit replacement, signing again or transport retry.
- Original delivery expiry, narrowed processing windows and monotonic continuity
  still apply. Historical verification does not make an expired delivery live.
- The same fixed processes, descriptors and dedicated role keys are used. No
  generic credential reader, extra key export or new privileged identity is added.

## Still unfinished

An already retained intent signed under a retired distinct intent authority
still fails current-authority admission; this bridge does not re-sign or replace
it. Its independent historical readmission remains work to complete.

The subsequent [LIVE release connection](control-plane-live-release-history.md)
uses separate fresh approval and current R2 grants over the same historical
evidence. It does not reuse proof-preparation permission. `retained-release`
still requires its own historical authority integration and retains its
current-only gate. Explicit older-source replay adapters and delivery-key
migration also remain separate work. H05 is not closed by these connections,
and no production acceptance gate advances from a source change.
