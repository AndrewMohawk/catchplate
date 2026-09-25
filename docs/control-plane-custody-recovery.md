# Control-plane custody recovery

Source-only `.121` implementation; unbuilt and unexecuted. These admin routes
inspect the existing cold-started caller journal and explicitly reconcile an
attempted record. They do not provision storage or create a new custody owner.
See [the journal boundary](control-plane-custody-journal.md) for provisioning,
quotas, immutable originals and the one-attempt barrier.

## Portal workspace

The portal's **Custody recovery** workspace provides manual inventory refresh,
25-record pages, per-record local inspection, and explicit readback only for
attempted records. It never polls or reconciles automatically and has no resend,
reset or delete control. Metadata stays in memory and is cleared when the
operator token, sign-in/session identity or roles change; obsolete in-flight
responses are discarded. An entered token may reveal the workspace before its
role is known, but the server must admit `admin` before any metadata is returned.
Unavailable custody remains separate from the other portal workspaces.

## Admin API

All three routes require the current `admin` role through the normal refreshed
authorization dependency. Query strings are rejected. Responses expose only
whitelisted metadata and use no-store/no-cache headers.

| Method and path | Result |
| --- | --- |
| `GET /api/authority/control-plane/custody` | Bounded local metadata inventory and count; no remote lookup. |
| `GET /api/authority/control-plane/custody/{local_digest}` | Local record metadata and its checked first stored observation, or `null`; `freshReadback: false`. |
| `POST /api/authority/control-plane/custody/reconcile` | One actual authenticated readback and exact-original comparison, followed by the first local observation; `freshReadback: true`. |

The path digest must be canonical `sha256:` followed by 64 lowercase hex digits.
The POST accepts only the closed JSON object `{"localDigest":"sha256:…"}` with
that same full digest shape. It requires exact `Content-Type: application/json`,
a `Content-Length` header, and a body no larger than 256 bytes. Normal CSRF
validation applies to cookie-authenticated requests. Callers cannot supply raw
originals, keys, configuration, source revision, deadlines or another endpoint.

Inventory entries contain `localDigest`, `family`, `selector`, `sourceRevision`,
`preparedBytes`, `attempted` and `observed`. An observation contains the local
digest, retained-record digest, first retention timestamp, and its original
configuration/source provenance. Neither GET performs a fresh remote read.
The API serializes `retainedAtEpochNs` as exact decimal text so JSON clients do
not round the nanosecond value; the internal journal/client keeps its integer.
Record inspection does revalidate the stored prepared content and any existing
attempt/observation identities on disk, without returning the original bodies.
POST preserves the first observation rather than rewriting it: an older first
retention timestamp or observation configuration does not become current merely
because a fresh read matched it.

## Outcome boundaries

| Status | Meaning |
| --- | --- |
| `404` | The local inventory lacks this record. It does not establish remote absence. |
| `409` | The local record has no delivery attempt and cannot use reconciliation. |
| `503` | The configured owner, transport, local observation or authenticated readback is unavailable. The outcome remains uncertain. |

These errors report `remoteState: "unknown"` with a fixed error code, not an
underlying filesystem or transport error string. Invalid requests and failed
authentication/authorization retain the normal HTTP validation errors.

Reconciliation requires the existing irreversible ATTEMPTED marker. It uses the
real historical control/plan verification and current lookup path, compares the
returned originals, and durably records the first matching local observation.
`freshReadback: true` means this request performed that readback; it is not a
signed remote receipt, proof of durable future storage, or business completion.
An unavailable or missing remote result never authorizes a repeat write.

No route returns original plan/history bytes, keys or paths. There are no HTTP
append, forwarding, attempt-reset or public business-execution actions here.
Reconciliation neither clears ATTEMPTED nor renews historical execution authority.

## Explicit journal-before-forward client

The private `ControlPlaneCustodyClient` also provides
`append_and_forward_evidence(purpose, originals)` and
`append_and_forward_transition(operation, originals)` for already prepared
raw-six/raw-seven records. Each completes the actual durable append before
calling the unchanged `forward_once` exactly once. Existing attempted records
remain spent; no automatic retry or marker reset occurs.

Success returns `CustodyForwardObservation(local_digest,
retained_record_digest, retained_at_epoch_ns)`: a local recovery identity and
an unsigned peer observation, not a receipt or business-success result.

An append failure propagates without forwarding. An ordinary exception after a
successful append becomes `CustodyForwardOutcomeError`, whose canonical
`local_digest` identifies the exact retained record. Its message is constant and
the underlying cause display is suppressed; originals and underlying error
strings are not formatted into it. The error does not assert that forwarding
reached the network or committed. Inspect local attempt state before choosing
the explicit read-only reconciliation action.

`KeyboardInterrupt` and `SystemExit` propagate unchanged rather than becoming
ordinary forwarding errors. Durable IDs remain discoverable through the
existing journal inventory/recovery path; cancellation does not clear an
attempt or prove that a remote write did not occur.

Implementation: [HTTP routes](../serverware/app.py),
[metadata recovery owner](../serverware/control_plane_custody_recovery.py), and
[caller client](../serverware/control_plane_custody_client.py). This document
describes source behavior only, not tested or deployed recovery proof.

Consolidated verification still needs to cover real cold-started ownership,
journal/attempt/observation integrity, authorized and denied HTTP requests,
malformed/oversized bodies, exact timestamp preservation, unavailable and
conflicting readbacks, and browser authentication changes during in-flight
requests. Those checks must establish that no recovery action resends retention
or turns an unsigned observation into business completion.
