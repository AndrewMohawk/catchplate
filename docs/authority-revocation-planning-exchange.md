# Authenticated verifier/planner exchange

Source `.71` connects private, measured verifier and planner methods through
an original-byte planning protocol. It implements real root acquisition,
authenticated planning and independent response replay; it does not activate
the public revocation dispatcher or complete execution. The current source is
unbuilt and unexecuted.

```text
admitted request/evidence + original reservation context
  -> verifier-owned root read -> closed read scopes -> owned full inventory
  -> signed control + four detached originals -> peer-checked planner socket
  -> authenticate originals -> genuine read-only observed planner
  -> closed read scopes -> original signed plan + evaluation context
  -> verifier replay against its held request/context/roots -> original pair
```

## Held configuration and genuine planning

`AuthorityProcess._request_revocation_observed_plan` accepts request, evidence,
nine-field historical context and existing work. It accepts no root inventory,
key, clock or successful proof. It holds measured configuration and the
descriptor-loaded verifier signer, owns the caller graphs and full payload,
then uses the active verifier's read-only DSN and configured database/TLS/query
pins to construct the actual `RevocationRootReader`. The actual inventory is
captured after normal read-scope exit, before generation-last capture.

The fixed client reowns these inputs, maps genuine configured keys and scope,
pairs the verifier signer and signs the planning control. The measured planner
endpoint, UID/GID, timeout and age are held before callbacks. Both client and
receiver enforce the existing planner `enabledOperations` allowlist; a valid
signature does not enable a disabled operation.

The planner-only server branch requires the existing verifier peer identity
and complete request EOF before allocating one source-capped work object.
`_produce_revocation_plan_from_request` holds its measured payload and signer,
then captures active planner admission, the read-only descriptor and generation
in that order. The fixed receiver validates the five originals and genuinely
maps the same configuration/launch scope. It authenticates the verifier control
before decoding the detached bodies or opening the planner database.

The receiver calls the actual `RevocationObservedPlanner.produce_observed` with
owned authenticated inputs and its fixed ten-slot configuration. Its real
read-only transaction, manifest checks, observed-root comparison, planner
production and lazy registry gate remain intact. It releases only original
plan/context bytes after normal read-scope exits. The client then calls the
genuine configured `verify_handoff` against its own retained request, context
and independent inventory. Response fields never choose those expectations.
An ordinary authenticated input carrier is not accepted as external authority.

## Exact wire and freshness

The control retains the exact eleven-field internal/v3 envelope with purpose
`produce-revocation-observed-plan` and the measured configuration digest. Its
closed seventeen-field payload binds source/generation,
capability/planner/operation/request scope, deadline and four original-body
digest/count pairs. The stable envelope ID is
derived from planner transaction ID and request digest. The full root inventory
has the existing ordered seven business roots, two authorization roots and
nine counted heads; its wire does not establish reader provenance by itself.

`serverware.policyAuthorityRevocationPlanningTransfer/v1` uses an eight-byte
`SWRP\0\0\0\1` request magic, five big-endian 64-bit lengths and five originals.
The response uses `SWRS\0\0\0\1`, two lengths and the original pair.

| Direction | Original body order | Individual byte caps |
| --- | --- | --- |
| Request | control, request, evidence, context, root inventory | 4 MiB, 64 MiB, 64 MiB, 512 KiB, 512 KiB |
| Response | signed plan, evaluation context | 64 MiB, 512 KiB |

Each direction has a 64 MiB aggregate cap, admitted before body allocation.
The client checks the actual peer before sending, half-closes its request and
requires response EOF. The server checks its peer before the prefix and
requires request EOF before planning. Each side has one absolute monotonic
I/O deadline; the server's starts before worker queuing. There is no detached
JSON error union, automatic resend or re-signing. Existing writer transfer v1
and legacy canonical handlers retain their own contracts.

Freshness uses the stricter measured verifier/planner internal age and
configured plan age, with the source clock-skew bound. Guarded monotonic then
epoch samples check original historical times: before signing, after signing
before transfer, after request authentication immediately before planning,
after planning, and after independent response replay. Historical context and
deadlines are never retimed. Checks after synchronous crypto/database work
prevent late publication; they do not preempt that work. Transport deadlines
also do not include earlier root acquisition or proof work.

## Evidence boundary and remaining work

All captures, canonical joins, signatures, root acquisition and replay consume
their real cumulative allowance within the owning invocation; subordinate
workers receive no fresh budget. Local body caps do not promise that every
maximum-size input fits cumulative proof limits. No writer credential,
persistence operation, new schema/privilege, peer exception or native resource
allowance is introduced. The `.71` source cutover requires matching measured
configuration/artifact/generation closure, not a new configuration schema.

This implementation-first tranche defers expansive new behavioral/source
suite authoring until functionality is complete, followed by the consolidated
frozen-build verification phase. Four framing methods are authored but
unexecuted. This is not a coverage-complete checkpoint or serving evidence.

Upstream public request/reservation admission, the complete public orchestration
through writer custody and terminal execution, current-root/witness authority,
historical key/recovery policy and uncertainty reconciliation remain unfinished.
Planning neither completes a reservation nor freezes roots for later writes.
Registry closure and the four unfinished WebAuthn kernels still prevent real
startup. Dependency publication, independent production services and signer
provisioning, immutable preparation and release/verification gates in
[goal.md](../goal.md) remain mandatory. No build, test, parser, interpreter, SQL
or runtime verification has been run for this tranche.
