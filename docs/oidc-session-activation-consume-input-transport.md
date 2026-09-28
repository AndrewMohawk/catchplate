# Fixed consume-input issuance transport

Source only, unbuilt and unexecuted. This fixed framing carries the actual
activation originals needed to request consume-planner and history-custody
originals. It neither issues authority nor starts, provisions or authenticates
an issuer service. The caller must independently retain and admit returned
originals; a socket peer or bounded frame is not planning permission.

The sole endpoint is
`/run/serverware/oidc-session-activation-consume-inputs/grants.sock`.
The service admits caller peer `65532:65532` before request bytes; the caller
checks the root-created listener peer `0:0` before sending. The exact endpoint
tuple contains that path, an integer timeout from 1 through 30 seconds, and both
zero peer IDs. The timeout can only tighten the inherited absolute deadline.
No arbitrary endpoint, resource selector or generic configurable profile exists.

## Exact request originals

Request magic `SWOCIQ01` carries raw17 in this order:

| Frames | Original data |
| --- | --- |
| 0 | `issue-oidc-session-activation-consume-inputs` |
| 1–4 | Existing activation completion raw4: status, completion-request identity, signed completion control, state ACK |
| 5–6 | Signed activation plan, encrypted activation execution bundle |
| 7–9 | Signed reserve request, reserve ACK, canonical snapshot |
| 10–13 | Activation caller authorization, grant, caller enrollment, grant enrollment |
| 14 | Activation-expectations original |
| 15 | Complete before-vector original |
| 16 | Ephemeral exact 64-byte old token |

Frames 1–13 preserve the actual consume plan's activation-original raw13 order
and limits, exported by the existing consume planner transport. Completion
framing is checked by its real raw4 shape helper, not treated as authenticated
completion. The remaining activation originals, expectations and before-vector
must be nonempty bounded originals. Expectations use the actual execution-
expectations cap; the before-vector uses its actual 64 KiB cap. The old token
retains the existing 64-byte URL-safe grammar. The producer receives the raw16
suffix, not a successful completion or planning object.

No JSON, signature, target, commit, key, history or present-state admission takes
place here. Shape-compatible uncertain completion frames are not permission to
issue inputs. No request frame or token is journaled or logged by transport;
composition must never persist this plaintext-possession request.

## Opaque response and complete bounds

Response magic `SWOCIR01` carries exact raw2: consume-planner bootstrap first,
history-custody original second. Caps come from their actual contracts: 4 MiB
and 8 MiB respectively. Each frame permits zero through its cap bytes, allowing
durable retention before interpretation/admission. Empty or malformed original
bytes are not success. There is no status, error or uncertainty response frame.

Headers contain eight magic bytes and one unsigned eight-byte big-endian length
per frame: 144 request bytes and 24 response bytes. The maximum request is the
smaller of its individual frame-cap sum and the 64 MiB whole-exchange ceiling
minus both headers and the entire 12 MiB reply. Large ciphertext bounds cannot
enlarge the exchange. Every length and the aggregate are checked before body
allocation; all body buffers/copies are precharged together on the same work.

## Original allowance and socket ownership

```text
_originals(values, *, response)
_recv_request(connection, *, deadline_ns, work, current)
_send_response(connection, originals, *, deadline_ns, work, current)
_socket_request_on_work(endpoint, *, originals, deadline_ns, work, current)
```

Server helpers reuse actual guarded release chunks and preserve the accepted
socket's existing ownership; they never close or detach it. Native calls retain
real current checks outside stable-ledger callbacks. Exact EOF is mandatory.
The caller uses only the generic engine's thirteenth literal entry,
`_consume_inputs_on_work`, with the actual cumulative work, original deadline
and positive epoch-returning current guard. It owns and closes its single
socket once, suppresses replies on guard/EOF/close uncertainty, and never
reconnects or retries. No new work ledger, clock window or currentness follows
from request data, timeout, response status or transport success.

Root issuer policy, signing keys, actual resources, request-scoped acquisition,
private history replay, planner admission and service lifecycle remain separate
responsibilities. Framing alone supplies no runtime or production evidence.
