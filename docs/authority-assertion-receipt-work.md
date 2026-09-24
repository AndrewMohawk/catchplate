# Shared work accounting for assertion-receipt verification

## Scope and trust boundary

The private measured worker in
[`authority_webauthn_assertion.py`](../serverware/authority_webauthn_assertion.py)
executes the genuine pinned-verifier receipt checks under an enclosing
computation's remaining work allowance. It does not accept a previous verifier
result as authority, replace signature verification with a digest comparison,
or authenticate a physical WebAuthn device directly.

This source is unbuilt and unexecuted. The public
`verify_revoke_assertion_evidence` signature and unmetered behavior remain
unchanged. Planner registration, database acquisition, root currentness,
capability admission and production activation are not introduced here.

The verifier key and identity, operation/request/capability bindings, trusted
current time, deadline and maximum age must come from independently admitted
context. They must not be selected by the retained proof bundle or receipt.
Successful verification returns the actual immutable snapshot only after the
existing binding, lifetime, signature and signed-byte checks succeed.

## One shared meter and a separate signature-attempt bound

The private `_ReceiptWork` wrapper retains the caller's exact `_ValidationWork`.
It creates no replacement hash/byte/node budget and does not reset or refund
previous spending. The caller must already own its input graphs; this worker
does not capture every input before its first cryptographic operation.

Ed25519 verification is not equivalent to one SHA-256 invocation. The wrapper
therefore permits at most one verification attempt, spent before calling the
actual pinned key's verifier. A rejected signature still consumes that attempt.
The future composer must create one wrapper and reuse it throughout its
invocation; constructing another wrapper is not a globally deduplicated budget
operation or a permitted way for a helper to replenish that allowance.
Exhausting this receipt-specific attempt policy raises `AssertionEvidenceError`;
the underlying shared hash/byte/node budget retains `QueryReadWorkError`.

Successful receipt verification performs eight explicit SHA-256 computations:
operation identity, receipt commitment, verifier-signature digest, RP-ID hash,
authenticator-data digest, client-data digest, assertion-signature digest and
client-challenge digest. It also performs one real Ed25519 verification and five
base64url decoding/canonicalization roundtrips. Cryptographic library internals
are not represented as fictitious extra SHA-256 calls.

## Allocation and traversal accounting

Canonical encoding, copies, text encoding and comparisons are prepared before
their actual work. Base64url preparation includes the whole actual roundtrip,
not only its decode: scanning, padding, intermediate encodings, decoding,
canonical re-encoding and comparison all remain bounded.

Client JSON is opaque signed bytes until the actual parser runs. Measuring the
parsed result afterward cannot bound the parser's prior allocation. The measured
path therefore reserves decoding, parsing and duplicate-object construction
work before the real `json.loads` call, and bounds structural depth before that
call. The real duplicate-field rejection and client-ceremony checks remain
authoritative; a preflight is not a replacement JSON parser or acceptance result.

For a base64url input of `L` characters, let `P = 4 ceil(L/4)`,
`D = 3(P/4)` and `R = 4 ceil(D/3)`. These are conservative padded-input,
decoded-output and canonical re-encoded-output bounds. Before scanning or
calling a codec, the worker reserves `2L + 4P + 2D + 5R` bytes and zero JSON
nodes. This includes input alphabet scanning and both equality operands,
padding/ASCII/URL translation/decoder input, decoded output/encoder input,
and encoding/URL translation/ASCII decoding/padding removal. The actual codec
still rejects invalid alphabets, padding bits and signature lengths.

For canonical ASCII JSON of length `L` and `N` nodes (including object keys),
the shared helper's encoding and conservative copy preparations cost `2L/2N`.
Comparison preparation costs that amount for each operand. Raw UTF-8
measurement/encoding costs twice the UTF-8 byte length and two scalar nodes.
Each of the six text fields also prepares the real strip copy, both strip
comparison operands and character scan: `8L/8N`, plus its raw UTF-8 preparation.
The successful body has two actual canonical encodings and 17 prepared
variable-value comparisons. The unsigned-receipt filter conservatively charges
the full source snapshot, not just its smaller result. Fixed-size digest syntax,
hex formatting, scalar guards and 32-/4-byte authenticator fields are bounded
scaffolding, not claims to count every instruction.

For client data of `U` raw bytes, the structural scan is charged `U` bytes
before scanning. UTF-8 decoding, parsing and duplicate-object construction then
reserve `3U` bytes and `2(U+1)` nodes before their allocations. The total is
`4U` bytes and `2(U+1)` nodes. `U+1` conservatively bounds a valid JSON graph's
nodes; quoted delimiters and escapes must not be mistaken for structural depth.
The ceiling is 128 simultaneously open containers, counting the root as one.
This is a conservative parse guard, not an exact JSON-node-depth measurement.

The existing 4 MiB receipt bound and 4 KiB text-field bounds remain semantic
limits, independently of cumulative work. Conservative preparation can reject
an input within a local size cap when its remaining computation budget is too
small. The measured path also requires exact lossless input graphs; a shared
helper can reject an invalid representation before the receipt's own validator.

These are defined work units, not exact Python allocation sizes, elapsed time,
or a transport-size guarantee. Conservative reservations remain spent even when
the actual graph is smaller. Shared work exhaustion does not become successful
receipt verification and does not waive any semantic check.
The signature-attempt counter is private computation state, not a new persisted
proof field, signed authority claim or replacement receipt.

## Integration still required

The [retained revocation proof](authority-revocation-proof-bundle.md) does not yet
invoke this measured worker. A future semantic composer must bind the returned
verified assertion IDs to its owned proof inputs, run the actual revocation
kernel, apply the [shared capacity finalizer](authority-audit-capacity-work.md),
and compare the resulting mutation set with the genuinely proved writes.
Repeated work receives no discount merely because another phase saw the same
bytes, keys or rows.

The [18 authored controls](../scripts/test_webauthn_assertion_work.py) use real
synthetic Ed25519 signatures and independent expected commitments/work totals.
Source review and authored tests are not runtime evidence; the approved
consolidated verification prerequisites
and exact frozen source/artifact closure remain mandatory.
