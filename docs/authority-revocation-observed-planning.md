# Independently observed revocation planning

## Status

Source `.53` connects the private independent root inventory to genuine plan
production and configured persistence. It is **unbuilt and unexecuted**. This
is an internal composition, not an enabled request route, accepted release,
live PostgreSQL demonstration or completed credential revocation. The public
registry gates remain closed.

The [verifier root reader](authority-revocation-root-observation.md) obtains its
own database observations before planning. Neither a root-inventory dataclass
nor a signed plan grants authority by construction. Independently admitted
processes, keys, source configuration, reservations and clock provenance are
still prerequisites.

## Expectations must precede the plan

The existing exact-context API is retained. The successor takes independent
context without `expectedBefore`, together with the complete verifier-owned
inventory: seven business roots, two authorization roots and nine counted
heads. It captures that data before database or signing callbacks.
The producer receives fourteen context fields. The configured coordinator
accepts twelve, adding its fixed planner and verifier identities itself;
neither caller supplies a proposed before-root vector on this path.

```text
independent verifier snapshot: 7 business + 2 authorization + 9 heads
                                |
                          owned expectations
                                |
actual planner reads / assertion / effects / write-proof acquisition
                                |
          compare the complete independently expected inventory
                                |
       actual read/write profiles select an independent subset
                                |
             proof packaging, original context bytes, signing
                                |
              capture independent context; close read scopes
                                |
             real configured persistence and retained replay
```

The full comparison includes any counted heads that the final mutation does
not use. A drifted unused head is not silently dropped. The exact signed set
(which may still contain all nine heads) is selected only after genuine
acquisition and mutation derivation establish
which source profiles the operation actually needs. Selected values come
from the independently captured inventory, not from the plan's claims.

The planner joins table/index identity, root revision, root digest and count.
Its tuple-valued primary observations are explicitly rendered as bounded
wire lists before the strict full-vector shape check.
The reader separately validates auxiliary primary descriptor fields and
counted profile/manifest bindings. This is not a claim that the planner reads
every auxiliary field again, or that equal roots prove population freshness
at a later execution.

## The same independent context reaches persistence

The successor producer returns its original signed envelope, evaluation
context bytes, actual planner database cutoff and independently projected
expected context. The configured coordinator captures and validates that
context before read-exit callbacks. Non-root pins must still match the
original independent input and configured identities.

Only after all read scopes exit successfully may the separate writer open.
Writer expectations come from the captured independent context. The existing
retained-record worker still verifies original bytes and replays genuine
proofs; neither a producer result nor a context dataclass substitutes for
that verification. The coordinator also retains the independent context for
subsequent invocation history, instead of reconstructing it from signed or
stored output.

All variable captures, comparisons and actual proof/signing/replay work use
the same remaining invocation allowance. No wrapper supplies a replacement
allowance. Fixed source metadata, driver work and existing explicitly stated
accounting exclusions are not whole-process resource measurements. An error
aborts the invocation; consumed work is not refunded.

## Still required

Serving integration, authenticated custody of the original planner cutoff,
durable original invocation retries, execution reservation/issuance ordering,
post-plan witness binding, current-root one-use execution and atomic terminal
publication remain incomplete. A local UTC cutoff and independently owned
root graph are not authenticated cross-role provenance.

The four unfinished WebAuthn kernels, externally provisioned production
Nitro/KMS/signing/witness services and approved sealed verification
prerequisites remain necessary. Follow [goal.md](../goal.md): source review
and authored tests do not replace the frozen-source preparation and
sequential no-build verification phase.
