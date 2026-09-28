# Guarded activation caller transports

The three existing activation role transports now expose the same private
caller API:

```text
_socket_request_on_work(endpoint, *, originals, deadline_ns, work, current)
```

The authorizer keeps raw4 to raw1 and returns original grant bytes. The reserver
keeps raw5 to raw3 and returns reserve, snapshot and ACK originals. SQL keeps
raw8 to raw4 and returns the existing unsigned outcome originals. Their fixed
paths, root listener peer, magic bytes, individual limits, whole-exchange bounds
and older helpers are unchanged. SQL's existing uncertainty and empty-frame
grammar is not widened.

`authority_oidc_session_activation_caller_transport.py` shares only the bounded
I/O implementation. Three literal entry functions select the exact three
existing transport modules; its private engine rejects any other module. It
does not accept request-selected profiles, framing callbacks or arbitrary
endpoints. Shape-valid response bytes and a matching local socket peer are not
authorization, replay, commit, completion, currentness or token-release proof.

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

This is a source-only downstream caller seam. It does not establish completed
public activation dispatch, installed services, runtime success or production
readiness.
