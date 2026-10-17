# Private consume-planner transport

`authority_oidc_session_activation_delivery_planner_transport.py` defines four
fixed requests for the actual [cold planner](oidc-session-activation-delivery-cold-planning.md).
Framing and socket credentials admit no plan, completed activation, execution,
current session, fresh public permission or token-release authority.

| Branch | Magic | Exact original frames |
|---|---|---|
| Prepare | `SWODPQ01` | raw15: fixed purpose, original old token64, activation raw13 |
| Bounded prepare | `SWODPQ02` | raw16: distinct fixed purpose, original old token64, activation raw13, caller's original epoch ceiling |
| Verify retained | `SWODVQ01` | raw4: fixed purpose, known signed consume plan, original deadline, journal digest |
| Export retained | `SWODXQ01` | raw4: distinct fixed purpose, known signed consume plan, original deadline, journal digest |
| Prepare/verify response | `SWODPR01` | raw6: status, typed request, scope, plan, plan digest, journal digest |
| Export response | `SWODXR01` | raw7: status, typed request, scope, plan, encrypted originals bundle, plan digest, journal digest |

The original purpose bytes remain `prepare-oidc-session-activation-delivery-plan`
and `verify-retained-oidc-session-activation-delivery-plan`. Their response status is
`prepared`, `verified`, or `uncertain`; uncertainty requires all five suffixes
empty. Export uses `export-oidc-session-activation-delivery-plan`, with status
`exported` or `uncertain`; uncertainty requires all six suffixes empty. Clients
reject the other response magic and a successful status belonging to another
request branch. Export carries only the distinct consume
[encrypted bundle](oidc-session-activation-delivery-execution-bundle.md), never
the private journal plaintext or a key. Its bounded frame check is not AEAD
authentication or original-proof replay.
The exact activation raw13 order remains the existing completed-response raw4,
activation plan, encrypted bundle, reserve, reserve receipt, snapshot, caller
authorization, grant, caller enrollment and grant enrollment. Shape is not proof.

Bounded prepare uses the distinct literal
`prepare-bounded-oidc-session-activation-delivery-plan`. Its final frame is a
canonical positive i64 epoch integer in ASCII, at most 19 bytes, with no leading
zero. The guarded caller derives it from its already-held `live_window[3]`;
there is no separate caller-selected policy or renewed interval. The actual
service narrows its existing pre-read window and deadline before calling the
cold planner, preserving the original first three clock samples, age/skew
policy and inherited monotonic ceiling. The supplied epoch can only tighten
that real window. The actual plan scope therefore uses that narrowed deadline,
not a later service opening or substituted historical clock. Response remains
`SWODPR01` raw6. Legacy `SWODPQ01` remains strictly raw15 and its old client does
not dispatch the new bounded profile.

Known-plan replay requires an independently retained original positive deadline
(canonical ASCII, no leading zero, at most 20 digits) and exact `sha256:` journal
digest. Neither is learned from a storage lookup or substituted from current
time. `_retained_scope(originals, work)` supplies the service's sole bounded
decoder for exactly the retained-verification or retained-export raw4 branches.
No request-selected policy, subject, roots, keys or execution operation
is present; those come from root-authenticated cold configuration.

The fixed endpoint is `/run/catchplate/oidc-session-activation/delivery-planner.sock`,
timeout 1–30 seconds. Service identity is UID/GID 65501 and `_recv_request`
checks caller UID/GID 65532 before reading even the prefix. Client peer 0:0
means the root-created socket-activation listener; it does **not** attest that
the executing server is UID 65501. Dedicated launch/resource admission remains
necessary; this module does not provision socket access.

The original I/O entrypoints require the supplied `live_window`, inherited
`deadline_ns` and existing `work`. It only narrows the bound; no clock opening or
new work allowance exists. Source ceilings and all frame lengths are checked
before body allocation. Prepare/verify preserve their existing reservation of
the entire maximum raw6 response plus both headers inside the 64 MiB aggregate.
For export, `MAX_EXPORT_BUNDLE_BYTES` is the lesser of the codec ceiling and
64 MiB minus the maximum raw4 export request, both export headers, and every
other raw7 response field's maximum. Thus even a short actual request cannot
expand the fixed ciphertext cap; both receive directions check the conservative
whole-exchange ceiling before allocating bodies. Request/scope output caps are
2 MiB each, signed consume plan 16 KiB, digests 71 bytes; activation raw13 uses
its actual source-specific ceilings. Buffer/copy/read/write costs debit the
same work, including bounded framing and exact EOF.

Service APIs are `_recv_request` and `_send_response`; the latter and
`_originals(..., response=True)` use the explicit `export=True` branch for raw7,
while their default preserves raw6. The actual service must
keep its signed-plan expiry guard through sending and close for response EOF.
Private clients `_socket_prepare` and `_socket_verify_retained` perform one
fixed-peer exchange, half-close the request, require exact response EOF and
return unverified immutable raw6. `_socket_export_retained` takes the same
independent envelope/deadline/journal inputs as `_socket_verify_retained` and
returns unverified immutable raw7 through one fixed-peer exchange. The actual
[export owner](oidc-session-activation-delivery-execution-export.md), not a wire
status, is responsible for genuine retained replay and durable first-exact
ciphertext. No client accepts a successful result object or authority-producing
callback. There are no automatic retries, resealing, signing, decryption,
retained lookup, SQL or fallback paths here. A disconnect or uncertainty may follow durable retention;
it is never proof of absence or permission to prepare/sign again.

## Guarded prepare and export callers

The dynamic worker has separate server entrypoints:
`_recv_request_on_work(connection, *, deadline_ns, work, current,
maximum_request_bytes=None, expected_purpose=None)` and
`_send_response_on_work(connection, originals, *, deadline_ns, work, current,
export=False)`. These retain the actual original delivery/service guard before
and after each native readiness/read/write operation on the owned nonblocking
socket. The owner-selected phase is checked at the magic prefix; the optional
body cap is checked after fixed grammar lengths and before body allocation.
Neither can widen the existing raw15/raw16/raw4 and raw6/raw7 grammar or its
aggregate ceiling. The actual dynamic service selects only bounded prepare,
then exact retained export, on one original work/window.

The source-fixed guarded entrypoints are:

```text
_socket_prepare_on_work(endpoint, *, old_token_bytes, activation_originals,
    live_window, deadline_ns, work, current, maximum_response_bytes=None)
_socket_export_retained_on_work(endpoint, *, envelope_bytes,
    expected_deadline_epoch_ns, expected_journal_digest, live_window,
    deadline_ns, work, current, maximum_response_bytes=None)
```

Prepare selects bounded raw16 and returns unverified raw6. Export keeps the
existing raw4 request and returns unverified ciphertext-only raw7. The original
prepare, retained-verification and export helpers retain their existing wire
contracts. The new private I/O path accepts only bounded prepare and export;
it does not accept an arbitrary endpoint, codec or authority callback.

`current()` is the actual parent's current guard, returning a positive epoch.
It is composed around the genuine guard for the supplied window, with every
observed epoch retained and cross-checked for reversal. Both original monotonic
bounds remain enforced. No new clock opening, work ledger or allowance is
created. The local timeout and optional response cap only tighten existing
bounds; the response cap cannot exceed its fixed source maximum.

Call these charging helpers directly, not inside a stable-ledger native
callback. The actual parent/window guard brackets socket allocation, connect,
peer admission, each bounded send/receive chunk, half-close, exact EOF and
normal close. Work-counter rollback or changed limit identity is rejected.
The allocated socket is assigned to cleanup ownership before callback suffixes;
an invalid guard cannot prevent the one owned close attempt. Close uncertainty
suppresses the result and never triggers a descriptor or request retry.

Header/chunk work is charged before contact. All response frame lengths, the
caller-tightened response ceiling and whole-exchange limit are checked before
body allocation, then all response buffers/copies are precharged together on
the same ledger. The old token remains one exact 64-byte request frame: these
helpers do not log it, journal it or return it in a response. Parent claim and
retention code must not retain that request frame as plaintext. Shape-valid
output remains ordinary bytes, never accepted planning, export or execution
authority.

Source-only implementation: no runtime/build/test, listener installation,
production readiness or public route is established by this transport.
