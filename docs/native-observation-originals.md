# Native observation originals

The native shadow worker now retains the actual comparison inputs it previously
reduced to hashes. It places bounded public originals inside the real signed
custody append, using `policyShadowRuntimeAccountingEvent/v2` for successful
candidate-request and candidate-response observations under explicitly selected
native durable-delivery v3. The retained cold owner fixes that selection before
the lifecycle begins. Other events, older native delivery profiles and non-native
producers keep their existing v1 representation.

Request originals contain the actual active and candidate typed plans, signed
snapshot bindings, actual terminal-effect evidence and final-effect preimage.
The installed [signed classifier](compiled-route-authority.md) supplies authority
bindings only when the evaluator retained a genuine route, operation and
authenticated principal. Missing classification is explicit null, not a guessed
read/write class. No raw request, credential, header or response body is exported.

Response originals retain exact response-facts, bound active validation, the
actual active release decision and the candidate validator result. Their hashes
are the same commitments written into the existing request/response accounting
records. A rejection remains a rejected comparison, not a successful release.

Timing is measured at the actual callers with a monotonic clock:

- facts capture includes validation and ownership of the captured facts;
- active evaluation is the decision-time evaluation, not initial admission;
- candidate evaluation is the actual worker evaluation, including a measured
  fallback if no retained candidate result exists;
- response validation is the candidate response evaluator;
- shadow total runs from facts-capture start to that observation's construction.

Missing or unrepresentable samples remain null. Pure policy evaluators do not
read clocks. These timings are not benchmark or production performance evidence.

Originals are capped at 8 KiB, 512 JSON nodes and depth 32. Existing 16 KiB event,
64 KiB observation and complete-ledger bounds remain unchanged; overflows leave
the native canary unready. Queue accounting conservatively charges 512 KiB per
job for retained and temporary originals; this is a modeled budget, not RSS.
Receivers retain the complete signed bytes and recheck preimages and protected
compiler/publication associations without relabeling them as Fleet evidence.

This connects an evidence producer and its intake, not the complete readiness
assembler. Deriving the full semantic expansion, pilot membership, response
obligation/comparison and per-ingress `ObservationResult` still requires the
genuine originals and independently approved compiler scope. Native READY and
activation, remaining services and Setup are separate implementation work.
No build, test, runtime or production acceptance is claimed for this source.
