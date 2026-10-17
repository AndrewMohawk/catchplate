# Original signed revocation bytes

Source `.36` adds a private raw-byte entry point in
[`authority_revocation_wire.py`](../catchplate/authority_revocation_wire.py).
It connects bounded transport decoding to the genuine signed-plan verifier on
the caller's existing work object. It is **unbuilt and unexecuted**, not a new
service endpoint, durable record, registered kernel or SQL authorization.

## Input and parsing boundary

`_verify_signed_envelope_on_work` takes immutable original envelope bytes, one
existing `_ValidationWork`, and the verifier's mandatory independent inputs
other than `envelope`. There is no `limits` override, successful-result token,
caller-created ledger or stored-context shortcut. Both keys, the expected
request, identities, reservation, clocks, original database instant and before
vectors still require independent admission.

The decoder bounds the original bytes before any decoded text or JSON graph is
allocated. A prepaid lexical scan counts every value/container and object key,
checks nesting including scalar/key depth, and rejects non-ASCII input, invalid
escapes, NUL and lone surrogates. Valid escaped Unicode pairs remain supported.
The real JSON parser validates grammar; its object hook rejects duplicate
decoded keys, including aliases written with escapes. Floating-point and
nonfinite numbers are forbidden. Integer conversion uses bounded chunks with
the existing 16,384-bit ceiling, without changing interpreter-wide limits.
The downstream canonical encoder may impose a stricter integer conversion
limit; the decoder does not enlarge that accepted domain.

Embedded QueryRead JSON strings stay opaque strings. The transport decoder
does not recursively parse them or turn their contents into authenticated
observations. The existing proof engine performs its actual required work.

## Defined work and original-byte equality

For original byte length `B`, JSON token/node count `N` including keys, object
count `O` and object-member count `P`, successful decoding reserves:

```text
hashes: 0
byte work: 4B
node work: N + O + 2P
```

One `B` pays for the lexical scan. The next `3B` covers ASCII decoding, parser
input and a bounded callback allowance. `N` covers parser nodes; `O + 2P`
accounts for duplicate-hook dictionary construction and key/value references.
This is a defined conservative reservation, not a count of exact Python heap
allocation or a whole-process memory guarantee. The original received buffer
already exists and transport acquisition is outside this scope.

The private same-work verifier attaches its compact-proof hold after this
prefix. It executes the same capture, canonical encoders, actual planner and
assertion signatures, semantic replay and bindings as the public graph
verifier. No fresh allowance or successful proof object replaces those steps.
The actual canonical envelope encoder is compared with the original bytes
before signature verification, charging both byte operands (`2B`). Whitespace,
field order, escape spellings and number representations cannot silently
become a different retained envelope. No extra canonical encoder is introduced
for this comparison.

The returned envelope bytes therefore equal the input bytes. The producer's
mutable graph observations are not used to reconstruct or re-sign them.
Named verification phases remain exclusive deltas; overall metrics include
the decoder prefix and any prior work. Do not sum overall snapshots as phases.
Normal success and failure restore the entering limit object without refunding
counters; caught nested attachment poisons the active owner. An externally
mutated entering limit object is detected and denied, not silently repaired.
A failed phase aborts its enclosing invocation rather than creating a retry
allowance; that work object must not be reused after failure.
Both real public-key callbacks must leave the work identity, exact integer
counters and limit identity/values unchanged. These guards do not add another
work allowance or substitute for either actual signature verification.

## What remains

The graph verifier's public signature, default budget and existing phase
accounting remain unchanged. V3 field inventories, persistence, public routes,
registry and SQL consumers remain closed to this successor.

Source `.37` builds private [retained-record storage and replay](authority-revocation-retention.md)
on this original-byte verifier. It reuses the real decoder with tighter context
bounds; the envelope API and default bounds are unchanged. Public protocol
activation and installed-source migration remain separate. Stored historical expectations cannot establish current
roots, enrollment, reservation freshness or one-use execution. The source
controls include independent accounting and producer-to-raw-consumer fixtures;
none has been executed under the current implementation-phase gate.
