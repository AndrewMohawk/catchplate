# Configured verifier intent and planner relay

Source `.70` adds private configured producers for the existing
[detached writer commitments](authority-revocation-writer-commitment.md).
The verifier checks original plan/context bytes against its own database root
observations before signing an intent. The planner authenticates that original
intent and its detached bodies before signing a separate relay. Neither method
sends a request. The [configured writer client](authority-revocation-writer-client.md)
still takes all five exact originals and independently derives its ACK
expectations before transfer. This is authored, unexecuted source, not proof of
service admission, a database transaction or a completed public flow.

## Verifier ownership and independent roots

`AuthorityProcess._produce_revocation_writer_intent` accepts original plan and
evaluation-context bytes, an independent request and nine-field historical
context, original planned timestamp, execution/planner IDs and existing work.
It accepts no root inventory, successful handoff, key, clock or callback.
An independently admitted request/reservation and fixed IDs remain upstream
requirements; calling this private method does not establish that admission.

The method holds the measured configuration, digest and descriptor-loaded
verifier signer once. It bounds immutable bytes and scalars, owns the
request/context graph and joins the independent planner ID, then captures the
full configuration before external callbacks. Timeout, database role, TLS
client DN/serial/issuer and source query-manifest pins come from that same
owned payload. The measured timeout must be within 2 through 300 seconds and
is floored for libpq; no caller DSN or writer credential is accepted.

After guarded active-verifier admission and reading the verifier-only DSN
descriptor, the method constructs the actual `RevocationRootReader`. Its
PG16, current/session role, TLS, non-elevated privilege and serializable
read-only deferrable checks precede the real two-read inventory acquisition.
The reader returns only after its read scopes close. The method captures that
inventory before its final generation callback and calls the fixed producer
directly, without chaining a method that rereads mutable process configuration.

```text
held measured configuration, verifier signer and admitted request/context
  -> actual verifier root read -> normal read-scope exit -> owned inventory
  -> generation-last binding and configured original-byte handoff replay
  -> owned historical claims -> fresh clocks -> signed intent + history bytes

original intent + original plan/context/history + held planner configuration
  -> measured key/scope binding -> fresh clocks -> authenticate original intent
  -> separately signed relay bytes

same five originals -> configured writer client -> independently verified ACK
```

The inventory is ordinary owned data, not a transferable proof token. The inert
worker's direct-call precondition is genuine upstream read/configuration/launch
provenance; only the actual service adapter supplies that acquisition here.
Closing the read transaction does not freeze current roots for later writes.

## Genuine replay before intent signing

`authority_revocation_writer_producers._produce_intent_on_configuration`
reowns request/context, full inventory and full configuration on the same
allowance before mapper key callbacks. The genuine verifier mapper checks the
configuration and launch commitment, source manifest, pinned planner/verifier
keys and configured identities/policy. One fixed owner snapshot supplies the
keys and configuration/generation pins used through signing.

The actual configured `verify_handoff` replays the original bytes in this call.
Its authenticated cutoff and independently selected root values, not a caller
success object, supply the historical claims. It does not claim a full unused
head comparison. The resulting external fifteen-field graph receives a real
ownership capture before any clock/signing callback. Its exact UTC cutoff,
historical verification times and planned timestamp are retained.

Guarded monotonic then epoch samples check historical freshness using the
strictest measured internal age of verifier, planner and writer, with the
unchanged source skew. These are separate from the historical assertion and
plan-age policy. The existing pure intent producer owns the inputs again,
genuinely pairs the held verifier signer with its measured public key, rejects
planner-key reuse, hashes original bodies and signs/self-verifies the control.
The ordinary return is `(intent_bytes, historical_expectations_bytes)`.

## Relay, originals and retry boundaries

`AuthorityProcess._produce_revocation_writer_relay` holds the planner signer,
full measured payload and digest before guarded active-planner and final
generation callbacks. The fixed worker reowns the payload, maps actual pinned
keys and scope, then samples monotonic and epoch clocks. The existing pure relay
producer checks the original verifier signature, all header/body/history joins
and freshness using the stricter planner/writer internal age and source skew.
It pairs the actual planner signer, signs/self-verifies, and returns only the
original relay bytes. It does not repeat semantic replay or open a database.

Producing and sending remain separate. Stable intent/relay IDs exclude time
and body hashes, while durable custody compares exact signed originals. A new
signature or timestamp after delivery uncertainty is not an identical retry.
Callers must preserve original controls, history, plan and context; there is no
automatic regeneration, resend, historical lookup or recovery authority here.

## Work and remaining integration

All real ownership copies, canonical joins, configuration/key work, handoff
replay and pure producer work consume the same existing H/B/N allowance.
The intent's extra independent read uses the existing bounded reader accounting;
the full acquisition is not erased when the handoff selects relevant roots.
Clock/driver/native-key internals retain their existing exclusions. No new
allowance, local body limit, transport limit or native resource budget is added.

Source revision `.70` requires matching configuration/artifact/generation
closure. Configuration v2, transfer v1, credential descriptors, role peers,
database DDL structure and privileges are unchanged. No keys are provisioned.

The public dispatch and legacy planner route are unchanged. Authenticated
original-byte exchange between verifier and planner, upstream request/witness
admission, post-plan current-root execution, historical recovery and the full
public flow remain incomplete. Registry closure and unfinished WebAuthn
kernels remain real gates. Component/source fixtures are authored but
unexecuted; synthetic keys, roots or clocks do not establish measured admission
or independently operated PostgreSQL behavior. This checkpoint adds 22 authored
methods: thirteen behavioral component controls and nine source-linkage
controls. None has been executed. See [goal.md](../goal.md).
