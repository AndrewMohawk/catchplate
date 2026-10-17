# Separate planner relay and custody forwarding

Source `.72` connects two private operations over the existing measured
verifier → planner → writer topology. It is unbuilt and unexecuted, not a
completed public custody workflow or verified delivery.

## Two explicit phases

1. **Prepare a relay:** the verifier supplies four originals—intent, signed
   plan, evaluation context and historical expectations—to the planner. The
   configured verifier client authenticates the intent and body bindings before
   sending. The planner authenticates them with its configured keys, signs a
   separate relay and returns its exact bytes. The verifier authenticates that
   original relay and its bindings before returning it. This phase never
   contacts the writer or forwards a custody request.
2. **Forward retained originals:** a separate verifier call supplies all five
   originals, now including the relay. Both the verifier client and the
   planner's existing writer client derive independent nineteen-field ACK
   expectations through genuine control authentication and retained-plan
   replay before their sockets. The writer receives those same originals
   through its existing atomic request/ACK custody path. The planner verifies
   the original writer ACK, returns it unchanged, and the verifier independently
   verifies it against its own expected fields and measured writer key.

Neither phase automatically invokes the other, retries, or regenerates a
control. Before the potentially committing forwarding call, the caller must
durably retain the exact intent, relay, plan, evaluation context and history.
That durable caller orchestration and uncertainty recovery are **unimplemented**.
An absent, late or invalid ACK can follow writer commit; it proves neither
rollback nor permission to replace or regenerate the originals. A stable ID
alone is not retry authority. A valid ACK is a custody statement, not current
execution, current-root or historical-key recovery authority.

## Fixed admission and transport

The actual service methods bound originals and own full measured configuration
before active-role and generation-last callbacks. Relay preparation holds the
descriptor-loaded planner signer before callbacks; forwarding needs no signer.
Fixed workers repeat genuine configuration/launch binding, retain the measured
operation allowlist and use independent role identities, key/SPKI pins, peer
credentials and policy. Responses cannot choose keys, ACK expectations or
authority. Registry admission is not bypassed.

Guarded clock samples check held authenticated issuance/deadline scalars after
signing and immediately before sockets, including after real replay. Historical
times and planned timestamps are never retimed. These checks deny expired relay
publication and pre-send dispatch; they do not preempt synchronous proof work.
ACK verification establishes custody only, not a fresh execution window. Every
process invocation uses its actual cumulative work allowance without subordinate
resets.

`catchplate.policyAuthorityRevocationPlannerCustodyTransfer/v1` has two fixed
actions. All magics below are eight bytes; lengths are big-endian unsigned
64-bit integers, followed by opaque originals.

| Frame magic | Body order | Individual caps |
| --- | --- | --- |
| `SWRL\0\0\0\1` + four lengths | intent, plan, context, history | 4 MiB, 64 MiB, 512 KiB, 64 MiB |
| `SWLR\0\0\0\1` + one length | original relay | 4 MiB |
| `SWRF\0\0\0\1` + five lengths | intent, relay, plan, context, history | 4 MiB, 4 MiB, 64 MiB, 512 KiB, 64 MiB |
| `SWFA\0\0\0\1` + one length | original writer ACK | 16 KiB |

Each body is at least two bytes. Requests have a 64 MiB aggregate cap, with all
lengths admitted before body allocation. The client checks its actual pinned
peer before sending and half-closes the request; the server requires EOF before
application work, and the client requires response EOF. The server checks its
peer before reading the prefix and allocates one source-capped work object
after either complete request. Existing bounded I/O enforces one absolute
deadline per connection. There is no JSON error union or automatic resend.
Writer transfer v1 and planning transfer v1 remain unchanged.

## Evidence and remaining work

This tranche adds three implementation modules: custody transport, configured
client and configured receiver. It adds no tests; mechanical source-linkage
updates preserve 26 existing method IDs. Broad behavioral/full-flow coverage is
deferred under the implementation-first workflow, then consolidated frozen-build
verification. No test, interpreter, parser, SQL or runtime verification ran.

Public request/reservation admission, durable orchestration, uncertainty
reconciliation and end-to-end terminal execution remain unfinished, as do
current-root/witness and historical-key authority. The four unfinished WebAuthn
kernels and actual registry closure remain startup blockers. Dependency
publication, production infrastructure, signer provisioning and immutable
preparation/release gates in [goal.md](../goal.md) are unchanged. This tranche
does not widen schema privileges, credentials, peers, proof limits or native
verification resources.
