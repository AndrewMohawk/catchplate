# Private activation completion exchange and response admission

This source-only path requests recovery of one independently pinned packet and
authenticates returned completion originals. It is not a public permission
flow, proof of current session state, token release or SQL retry. No build,
test, socket execution, provisioning or runtime verification was performed.

## Fixed transport

[`authority_oidc_session_activation_completion_transport`](../catchplate/authority_oidc_session_activation_completion_transport.py)
uses `/run/catchplate/oidc-session-activation/completion.sock`, with the expected
root-created inherited listener's kernel peer UID/GID `0:0`. Actual service
request-peer admission occurs before body reads; it is not performed by this
client-side peer check. Installation and socket DAC remain separate.

Request magic `SWOACM01` carries exactly two immutable byte frames:
`recover-oidc-session-activation-completion` and a canonical `sha256:` packet
digest. Response magic `SWOACR01` carries exactly four frames:

| Status | Remaining original frames |
| --- | --- |
| `acknowledged` | Completion request digest, exact signed complete control, exact signed state ACK. |
| `uncertain` | Three empty byte frames; no IDs, observations or retry hint. |

Individual ceilings come from the actual completion-record codecs. The fixed
whole-exchange ceiling includes both magic/length headers and maximum response
before body allocation. Exact EOF, request half-close and one mandatory
inherited monotonic deadline cover the sole exchange; endpoint timeout may
only shorten it. Connections close on all failures, including cancellation.
No alternate endpoint, automatic resend or fallback exists.

## Genuine private receiving verification

[`authority_oidc_session_activation_completion_response`](../catchplate/authority_oidc_session_activation_completion_response.py)
provides `_verify_on_work` with original plan/bundle, caller/grant/enrollments,
reserve/snapshot/ACK, independent keys/configuration/authorization and pending
scope, exact historical custody owner, and current work/window/deadline.
Returned IDs or an externally supplied successful result cannot replace these
inputs. All external graphs and original references are held before callbacks;
originals plus response retain the existing 64 MiB aggregate bound.

The actual historical owner narrows current processing to its admitted role
before genuine [pending-completion admission](oidc-session-activation-completion-admission.md).
That admission replays the original caller/grant/private plan and independently
scoped reserve once. The receiver then verifies real enrolled completion and
state signatures, exact request/receipt identities, sequence/ancestry/fence,
every marker binding and the producer's canonical signed inner observation.
The observation's marker and full after-vector digest derive from actual replay,
not a response assertion. The expected authorization digest is independently
joined. Original completion observation time must fit its signed interval.

Current processing remains under the same cumulative work and narrowed real
window/deadline through final result creation. Historical original expiry is
not refreshed or substituted as a current clock. The private result contains
only exact complete/ACK bytes and their authenticated digests; no admission API
accepts that result as authority.

## One real client composition, no public AES handoff

`_request_on_work(endpoint, *, packet_digest, ...)` takes the same independent
originals and scope as the verifier, owns them before callbacks or socket I/O,
reserves the maximum response inventory, obtains the historical owner's actual
narrowed processing bounds, performs the fixed raw2 exchange and calls the
genuine receiver verifier on the same work. It accepts no sender callback or
successful proof carrier and performs only one full historical replay. The
service may frame its actual durable recovery originals without redundantly
running this receiving replay on the sending side.

The request's packet digest is a selector, not received proof: raw4 contains no
packet identity and this API makes no returned packet-identity claim. Receiver
verification deliberately requires private historical AES custody. Public
permission, retained caller handoff and response projection remain F08.5 work;
no old registration/control-plane role acquires keys through this API. Strict
current-source historical cohorts remain, not general H05 authority. Neither
the signed ACK nor a local successful exchange proves latest off-host state,
releases a browser token, activates a public session or authorizes retry.
