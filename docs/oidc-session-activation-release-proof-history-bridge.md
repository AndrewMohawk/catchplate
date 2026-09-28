# Current proof authority over historical consume evidence

Release-proof bootstrap v2 adds exactly one wrapped immutable original,
`currentActivationPlanner`, to the existing v1 inventory. Its signature and
payload domains are independently versioned; launch grammar, descriptors,
48 MiB bootstrap limit and 64 MiB aggregate ceiling are unchanged. Producer and
verifier keep their original keyword API. Proof v1 retains its strict same-root,
same-configuration and byte-identical state-enrollment checks.

## Three independent authorities

- R0 authenticates the original activation provenance and delivery key.
- R1 authenticates the consumed caller, planner and state enrollments.
- R2 signs the fresh completion outer authority, current proof/intent enrollments
  and proof bootstrap. It does not re-sign or reinterpret old evidence as current.

V2 requires genuine completion custody v2 with its distinct v11 completion
history. Those signed originals independently pin R1 and the original bridge
policy interval. The source-private `_current_activation_on_work` helper is called
only after the policy/bootstrap has genuinely admitted its own completion
original. It verifies the exact R2 planner original as a historical configuration
template and re-admits both R1/R2 state enrollments. Their **complete payloads**,
database and generation must agree; signature envelopes need not agree.

The R2 template supplies proof configuration/generation/runtime pins and current
key exclusions. Proof producer identity remains the exact receiver identity of
the fresh R2-signed completion authority; it is not replaced with a generic
planner role. Genuine R2 enrollment and original intent signature verification
still bind the exact release target, caller, receiver and intent lifetime.

## Same delivery key, not migration

Release custody remains its existing signed v1 format. For proof v2, its nested
planner bytes must equal `currentActivationPlanner` exactly. Its delivery-key
digest must also equal the genuinely admitted R0 activation planner's original
delivery-key digest. The fresh custody signs the exact activation request and
operation, delivery envelope/scope, intent digest and consume request; the proof
bootstrap joins these to the original completion packet and expected release.
This admits root/configuration rotation with the same delivery key and compatible
state. It does not authorize delivery-key migration or arbitrary state/generation
migration. Existing custody validation is not loosened.

## Actual protected producer

`authority_oidc_session_activation_release_proof_production._produce_on_work`
keeps its argument API. Its actual source-owned completion custody, not a caller
flag, selects the bridged branch. It reauthenticates that custody and uses the
class-selected completion-history context to obtain genuine R0 provenance and
the authenticated original bridge policy. The original policy's delivery-key
pin must match the current release custody. No AES key is extracted or added as
an input.

Committed capture, original enrollment checks and the complete committed replay
use R1. Fresh release custody, original intent verification, proof enrollment,
signing and genuine output admission use R2. Both signed state payloads are
compared again, and R0/R1/R2 purpose keys remain excluded from intent/proof reuse.
The returned historical guard has a base-only ancestor, never its owning
aggregate guard. Same-call owner/resource identities and original work/clock
floors remain checked through signing and receiving.

## Bounds and remaining gates

Before v2 nested body allocation, the bootstrap reserves its wrapped originals
and their bounded nested-original copies, plus eight current-template
representations, eight state-enrollment maxima and
64 KiB metadata. The producer reserves actual input representations, fixed graph
headroom and the actual completion-history capture before re-admission. Oversize
inputs fail within the existing ceiling; these are representation bounds, not a
process-heap guarantee. The historical template's launch is never renewed:
fresh independently signed outer intervals authorize processing, while the
original intent and delivery expiry remain hard limits.

This source-only connection is unbuilt and unexecuted. Public preparation is
enabled only by the separately reviewed actor/caller integration; it does not
close H05, historical protected release, older-source adapters or production
acceptance.
