# Guarded activation and consume caller transports

The five fixed activation and five fixed consume transport profiles expose the same private
caller API:

```text
_socket_request_on_work(endpoint, *, originals, deadline_ns, work, current)
```

The authorizer keeps raw4 to raw1 and returns original grant bytes. The reserver
keeps raw5 to raw3 and returns reserve, snapshot and ACK originals. SQL keeps
raw8 to raw4 and returns the existing unsigned outcome originals. Completion
keeps raw2 to raw4 and returns original completion outcome frames. Their fixed
paths, root listener peer, magic bytes, individual limits, whole-exchange bounds
and older helpers are unchanged. SQL's existing uncertainty and empty-frame
grammar is not widened.

`authority_oidc_session_activation_caller_transport.py` shares only the bounded
I/O implementation. Ten literal entry functions select the exact ten
existing transport modules; its private engine rejects any other module. It
does not accept request-selected profiles, framing callbacks or arbitrary
endpoints. Shape-valid response bytes and a matching local socket peer are not
authorization, replay, commit, completion, currentness or token-release proof.

The consume authorizer, reserver and SQL wrappers retain their separate
`/run/serverware/oidc-session-activation-delivery-execution/` socket paths,
magic bytes and role admission. They exchange raw4/raw1, raw5/raw3 and raw8/raw4
respectively. Their dedicated literal entry functions cannot select an
activation operation, and only the operation-neutral unsigned SQL response
grammar is shared. Original signature, enrollment, exact-plan and ancestry
admission belong to the [same-context consume dispatcher](control-plane-oidc-session-activation-consume-dispatch.md),
not this framing engine. Private consume replay remains in the isolated service.

## Original allowance and owned I/O

The caller supplies its actual cumulative work, inherited absolute monotonic
deadline and actual current guard. `current()` returns a positive epoch integer
while retaining the caller's independently admitted owner, permission, target
and original clock-window checks. The adapter retains every observed epoch and
rejects reversal; it preserves the work object and limit identity and rejects
work-counter rollback across the guard. The socket timeout only tightens the
supplied deadline. There is no replacement work ledger, processing window or
renewed authority.

Call this charging helper directly, not inside a stable-ledger native callback.
Current checks bracket socket allocation, connect, peer admission, each bounded
send/receive chunk, half-close, exact EOF and close. Guard calls remain outside
native callbacks because a genuine guard may itself charge work. Socket
ownership is assigned inside the allocation callback, so a failing callback or
guard suffix still leaves the actual allocated socket cleanup-owned.

Request chunk/header work and response-header allocation are reserved before
contact. All returned frame lengths and the whole-exchange bound are checked
before response bodies are allocated. The entire response's bytearrays, chunks
and immutable outputs are precharged together against the same remaining work.
An exhausted budget fails closed; a wire-size ceiling is not a fresh allowance.

The owned socket is closed once even if a current guard has failed. Any native,
guard, EOF or close uncertainty suppresses the response, and no reconnect,
redispatch or close retry occurs. Actual caller composition must retain its
attempt/uncertainty discipline and independently authenticate all returned
originals; these wrappers neither create that durable state nor accept a
successful result object as authority.

## Completion's unchanged selector and custody boundary

The completion wrapper uses the existing
`/run/serverware/oidc-session-activation/completion.sock` endpoint and
`SWOACM01` / `SWOACR01` framing. The service runs at UID/GID 65503 and admits
request peer 65532 before reading frames; the caller checks the root-created
listener's kernel peer 0:0. These distinct checks do not grant history custody
to the caller. The configured timeout retains its existing bounded grammar and
can only tighten the inherited deadline.

Request raw2 remains the literal
`recover-oidc-session-activation-completion` and one canonical packet digest.
This is the existing independently pinned selector profile, not authorization
derived from an unsigned SQL observation. A returned acknowledged raw4 is
`acknowledged`, completion-request digest, signed complete control (at most
256 KiB) and state ACK (at most 16 KiB). Uncertainty remains `uncertain` followed
by three empty frames. The returned identity is not an authenticated packet echo.
Completion's request-only `MAX_BYTES` is unchanged; the shared engine uses its
actual `MAX_EXCHANGE_BYTES` for response allocation and aggregate admission.

The wrapper neither decrypts nor accepts a history owner or successful result.
The existing full
[completion response verifier](oidc-session-activation-completion-response.md)
still requires actual completion-purpose historical custody at UID/GID 65503.
Calling the raw transport from 65532 does not make that private verifier usable
there, grant AES keys, authenticate commit from SQL, or establish completion.
Actual receiving composition must independently authenticate the appropriate
originals under its admitted role; no automatic resend follows uncertainty.

The separate
[completion dispatch profile](oidc-session-activation-completion-dispatch-transport.md)
uses a distinct fixed purpose and request magic with the signed caller
authorization original instead of a packet selector. Its launch-selected service
must join that original to genuine root-held authorization before using its own
packet pin. It does not loosen the existing selector profile or response grammar.

The distinct consume
[completion dispatch profile](oidc-session-activation-delivery-completion-dispatch-transport.md)
uses `SWODCM02` and the exact signed consume caller authorization. It is available
only with the consume service's independently signed launch `/v2`, whose request
peer is 65532; the legacy selector launch `/v1` still admits only peer 65497.
The isolated service remains 65497, while the caller checks the root listener
peer 0:0. The service joins the original authorization before using its own packet
pin. This ninth guarded profile preserves the same original work/deadline and
response grammar; neither a SQL locator nor a response status supplies authority.

The tenth literal profile uses `SWODCM03` / `SWODCR02` only for consume caller
`/v4` and independently signed service launch `/v3`. It appends bounded raw2
[release hints](oidc-session-activation-release-hints.md) to the unchanged raw4
completion frames. Those unsigned hints and encrypted delivery bytes are not
authenticated by the completion/state signatures. Later private proof must
independently authenticate their exact mapping before credential release.

This is a source-only downstream caller seam. It does not establish completed
public activation dispatch, installed services, runtime success or production
readiness.
