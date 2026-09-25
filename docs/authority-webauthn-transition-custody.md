# Private WebAuthn transition custody

Status: source `.107`, implementation only; unbuilt and unexecuted. This is the
private retention and authenticated lookup path for `webauthn.registration.finalize`,
`webauthn.trust.stage` and `webauthn.trust.complete`, not execution of those
business transitions. See the [successor overview](webauthn-successor-transitions.md)
for signed planning and the `.105` PostgreSQL custody checkpoint.

## Originals and authority

The plan remains four original byte strings: envelope, proof, inputs and
evaluation context. Custody additionally carries independently admitted
historical expectations. A copied plan context, stored row, successful result
object or current configuration cannot supply that historical authority.
Request, root/count-head, cutoff, invocation, policy and key provenance must
already be admitted by the caller. Genuine raw-four signature, proof and
semantic replay still runs on the same invocation allowance.

The verifier signs a dedicated retain-only intent binding the exact originals
and historical expectations. The planner authenticates that intent and replays
the originals before signing its separate relay. These controls bind the fixed
operation, configuration, launch generation, record identity and byte inventory;
neither is an execution capability or proof that the database committed.

## Preparation and explicit delivery

1. Verifier prepares the original intent and requests a relay from the planner.
   This raw-six request is `(intent, envelope, proof, inputs, context, history)`.
   The planner returns the original signed relay without contacting the writer.
2. The caller retains the exact originals and explicitly chooses whether to
   forward. Delivery is raw seven:
   `(intent, relay, envelope, proof, inputs, context, history)`.
   The verifier forwards to the planner, which sends those originals to the writer.
3. The writer authenticates both controls and genuinely replays the plan before
   the fixed PostgreSQL custody operation. The returned digest and first-retained
   timestamp travel back through the planner as ordinary peer observations.

Preparation never automatically forwards, signs replacement originals or
retries. Before a potentially committing forward, the caller must durably retain
the exact request originals needed for later reconciliation. That durable caller
orchestration is still unfinished; this source path does not provide it.

All three hops use dedicated eight-byte operation/action prefixes, complete
length vectors, exact EOF and a 64 MiB aggregate including controls. Controls
are individually bounded to 4 MiB. Clients check configured Unix peer UID/GID
before sending and use one absolute transport deadline. The actual measured
configuration preserves verifier → planner → writer topology, explicit
transition policy and distinct verifier/planner keys; no ACL is widened.

## Authenticated lookup

Source `.107` adds a dedicated verifier-signed, 13-field lookup control. Raw two
is `(control, independent history)`: the control binds the requested record
digest, complete history digest/count, fixed operation and current
configuration/generation. The planner forwards those same original bytes to
the writer without signing a replacement or a relay. Each hop authenticates
the control and history commitment before decoding or using that history.

The writer uses the actual retained-record SELECT and genuine historical
raw-four replay, returning only after normal transaction and connection exit.
This uses the existing SERIALIZABLE writer owner, not a newly restricted
database READ ONLY transaction; the lookup makes no application mutations.
The response is `(envelope, proof, inputs, context, record digest, retention time)`.
Planner and verifier each repeat genuine original-plan signature, proof and
semantic replay against the separately authenticated history before accepting
their received response. The response metadata remains unsigned: its timestamp
is checked against original plan history and the current future-time bound,
not treated as a signed durability receipt.

A fresh bounded lookup window permits retrieval after a historical plan has
expired, without renewing any plan, evidence or invocation time. Current pinned
configuration and source must still match the supplied history, and the control
must match the current generation; there is no historical key-rollover resolver.
Raw-two requests and raw-four
responses plus metadata retain the 64 MiB aggregate limit, preallocation length
checks, configured peers, absolute deadlines, exact EOF and one shared allowance
per serving invocation. No replay is claimed before originals are retrieved.
Missing records raise; they are not proofs of absence, rollback or permission
to retry or reconcile an uncertain earlier write.

## Commit and failure boundaries

The original intent/relay windows remain in force across authentication, replay
and transport. Writer composition checks them immediately before and after the
actual store operation inside the outer transaction, and again after normal
outer transaction/connection exit. The store separately
checks the original signed plan expiry and invocation deadline without retiming
either. Identical content must match every immutable field and preserves the
first stored timestamp; it does not gain a fresh lifetime.

The response is an **unsigned digest/timestamp observation**, not a signed
durability receipt. A failure after commit or during uncertain connection exit
does not prove rollback or absence and does not authorize an automatic retry.
Transport completion, source inspection and a returned ordinary object do not
establish tested deployment behavior or exactly-once business execution.

Authenticated retrieval is implemented at source level. Independent historical
resolution, durable caller retention/reconciliation, authorized recovery,
public orchestration and atomic successor execution remain unfinished. This
path does not keep roots current, reserve a logical operation, issue execution
authority or complete the public workflow.
Infrastructure admission and the consolidated runtime/build validation phase
remain separate release requirements.
