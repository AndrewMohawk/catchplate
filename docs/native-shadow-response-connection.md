# Native response capture to shadow evaluation

The native proxy retains the real TLS response through its existing verified
capture-persistence transaction and provider-send effect commit. After normal
final-envelope verification, exact release consumption, reflection checks and
durable-policy completion, the transaction passes that source-owned capture to
the shadow evaluator.

The retained owner cannot be deserialized or cloned. It carries the original
physical HTTP bytes, native capture/attestation envelope and signed persistence
completion. It is charged against the existing shadow queue budget before
retention across further custody calls. An interrupted transaction records
unavailable evidence when the owner is dropped; there is no recapture or replay.

The shadow join checks the actual pending dispatch commitment, policy, principal,
route, request method, raw-object digest and size, and released-response digest.
The existing strict HTTP parser supplies the entity body and framing. Physical
headers are sliced from the captured bytes, never rebuilt from normalized
headers. Native proof commitments keep native domains; they do not impersonate
legacy transport signatures.

The normal terminal accounting and candidate-response worker then receive the
bounded exact capture. All required terminal effects must genuinely complete.
Credential generation, lease and decrypt terminals use their actual retained
verified outer receipts. The injection path now retains its own verified
completion before returning to the caller; it cannot be overwritten or attached
after finalization. These owners do not stand in for nested OAuth operations.
Missing quota, credential or OAuth completion evidence remains unavailable.
Gmail hydration requires its separate actual metadata evidence; informational
response chains are not yet covered by this shadow join. The ordinary reqwest
path continues to report parsed-only capture as unavailable.

This source connection does not provide the still-missing complete detailed
readiness producer, compiled classifier mapping, deployment or pilot acceptance.
Build and end-to-end verification remain deferred to the connected pilot batch.
