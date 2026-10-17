# Private release cold bootstrap

`oidc_session_activation_release_bootstrap.py` admits a fresh, root-signed
`catchplate.signedOidcSessionActivationReleaseBootstrap/v1` original for the
fixed `oidc-session-activation-token-release` process, UID/GID 65502. This is
source-only resource authority, not a service, release proof or runtime claim.

The root selects exactly one profile. `live-release` requires genuine live
release custody and a separate storage authorization with checkpoint
`0 / null`. `recovery` requires the original custody through its distinct
historical admission, fresh recovery authorization, and separate storage
authorization with checkpoint `1 / exact outcome digest`. An interrupted
retained outcome cannot be treated as a fresh live launch. Historical custody
does not renew the old intent, proof, execution or delivery interval.

The closed signed payload independently pins configuration, database,
generation, runtime, receiver, caller, proof producer and state receipt, plus
the complete six-field expected release target. It contains bounded original
custody/storage/recovery records and their exact byte digests, the independent
storage scope9 and recovery scope11, the custody identity and delivery-key
digest. Live launches must omit recovery scope and original by using `null`.
Nested root signatures and all configuration/key/target/directory joins are
checked, not inferred from a successful material object or directory contents.
Recovery startup must additionally compare its actual retained record with
these independently signed producer, target and receipt pins before invoking
the genuine original-authenticating recovery owner.

## Resource boundary

The exact inherited descriptor inventory is fixed:

| FD | Resource |
| --- | --- |
| 198 | Original root public key |
| 199 | Original signed cold bootstrap |
| 200 | Original raw 32-byte delivery AES key |
| 201 | Already-opened exact outcome slot directory |
| 202 | Pre-authorized private listener |

The launch pins the directory's device, inode, UID/GID 65502 and mode 0700.
There is no global single-slot path, caller-selected path, path creation or
directory-derived checkpoint. The listener path is fixed at
`/run/catchplate/oidc-session-activation-token-release/release.sock`, with peer
UID/GID 65532 and signed socket/path device/inode pins. It is only validated and
preserved by resource intake; this bootstrap does not accept, frame or deliver
a request. No history key, signer, SQL/TLS credential or state client is part of
this resource inventory. The bootstrap itself performs no resource I/O.

## Current allowance and APIs

`_construction_on_work(work)` opens the real construction bracket before root,
key or resource reads. Both `_verify_on_work` and `_produce_on_work` require the
supplied `live_window`, `transport_deadline_ns` and same work ledger; neither
has an optional clock fallback. The verifier receives original
`bootstrap_bytes` and the independent root key. The producer receives a
captured payload and the actual root key pair, verifies nested originals,
precharges signing, and checks canonical signed output and payload readback.

`_ReleaseMaterial` contains captured original bytes and independent target
pins, not an input credential. Its `live_window` and `deadline_ns` preserve the
original opening and only narrow it by role/storage authority, recovery or
live-custody authority, original delivery expiry, original planner age/skew,
and the signed request timeout. `live()` preserves sticky current-clock
observations across the genuine original guards. The fresh launch interval
must fit every applicable fresh nested interval; expired custody is exempt
only in the fixed recovery profile, never the original delivery itself.

Role originals are capped at 16 MiB, the total original inventory at 64 MiB,
and the closed role graph at 1,024 nodes/depth eight. Native signature and hash
work uses the existing bounded ledger. Startup must reauthenticate the raw
original and preserve this same work/window/deadline through a permanent
same-PID privilege drop and use; no post-drop exec, serialized clock authority,
successful-carrier substitution or new allowance is authorized.

This trusted-host-local contract does not provision paths, create a checkpoint,
provide off-host/latest-state witness assurance, install a worker, implement
private transport/response verification, or authorize public/portal handoff.
Those remain separate row-16 integration criteria.
