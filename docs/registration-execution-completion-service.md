# Cold registration completion recovery service

This source-only, trusted-host-local service owns read-only recovery and durable
delivery of completion for `webauthn.registration.evidence.admit`. It does not
invoke the SQL issuer/executor, clear an execution attempt, finalize a credential
or activate a session. Its source and packaging are unbuilt, unexecuted and
uninstalled. [Explicit public actions](public-registration-handoff.md) are now
wired through the separately authorized live-original caller in source, not
deployed. **0 of 6 production acceptance gates are verified**.

The [SQL service](registration-execution-sql-service.md) may return an unsigned
commit observation or an uncertain outcome. Neither substitutes for this
service's genuine custody recovery, committed-state readback, signed completion
and authenticated durable state acknowledgment.

## Independent cold scope

The root-signed bootstrap binds actual configuration/generation, original
enrollments and configured keys, plus the exact packet digest, authorization
digest, historical replay expectations and pending sequence/head/fence. The
wire request cannot choose new history, roots, SQL, keys or an operation. Its
packet selector must equal the independently pinned packet.

The closed schemas are
`serverware.signedRegistrationExecutionCompletionBootstrap/v1`,
`serverware.registrationExecutionCompletionBootstrap/v1` and
`serverware.registrationExecutionCompletionLaunch/v1`. The bootstrap original
is at most 4 MiB; its signed launch is at most 300 seconds and request timeout
1–30 seconds. `_verify_on_work` authenticates originals before cold resource
selection; `_produce_on_work` signs independent claims, not proof of provenance.

The pending checkpoint is a root-authenticated claim supplied independently of
the incoming selector and retained acknowledgments. The signature is not a live
witness that a pending head remains current. A separate completion-delivery
journal checkpoint admits local recovery; the journal cannot nominate its own
trusted head from a scan. Reopening after uncertainty requires an independently
admitted checkpoint and the same original pending/packet scope, not a reset to
an earlier local prefix.

The actual enrolled completion key is distinct from computation, state and
execution-authorizer keys. There is no authority to sign replacement execution
grants or reserve requests. Present-caller permission and purpose admission
remain prerequisites for any future public caller; possession of a packet ID
or earlier grant is not public completion or finalization permission.

One cold launch accepts at most one connection, including rejection, then
exits. There is no automatic request or process retry. Separately admitted
recovery in a later launch can reuse retained originals; this does not reopen
the earlier execution window or permit SQL execution again.

## Process, descriptors and protected originals

The process mode is `registration-execution-completion`, UID/GID
`65515:65515`, with no supplementary groups. It accepts the actual control-plane
peer `65532:65532`. Its root-activated listener is
`/run/serverware/registration-execution/completion.sock`, pathname owner/group
`65515:65532`, mode `0660`. Client-side peer admission expects listener owner
`0:0`, not the dropped service UID.

Root delivery retains exactly five descriptors:

| FD | Original owner input |
| --- | --- |
| 198 | `/run/serverware/registration-completion-trust/root-public-key.pem` |
| 199 | Signed `/run/serverware/registration-completion-trust/bootstrap.json` |
| 200 | Actual activated listener |
| 201 | Sealed original completion Ed25519 key |
| 202 | `/var/lib/serverware/registration-completion-delivery` directory, `65515:65515`, mode `0700` |

The completion key source is
`/run/serverware/registration-completion-keys/completion-ed25519.pem`, root-owned
mode `0400`, at most 4096 bytes; root delivery seals its original before dropping
privileges. It is not returned on the wire. Local sealed custody is not an HSM,
hardware attestation or protection against a hostile privileged host.

Five root-owned TLS originals below `/run/serverware/registration-completion-tls`
are bound to the signed bootstrap:

| Files | Mode and bound per file |
| --- | --- |
| `ca.pem`, `custody.crt`, `commit.crt` | `0444`, 2 bytes–64 KiB |
| `custody.key`, `commit.key` | `0440`, group `65515`, 2 bytes–16 KiB |

The custody-recovery and committed-state readers use their separate actual
PostgreSQL roles and independently admitted per-role TLS identities. Privileges,
query/structural pins and same-database provenance must be provisioned, not
learned from observed data. Read-only mounts and file hashes alone do not supply
those authorities.

Both reader configurations now require eight fields, including the same
independently root-signed `structureManifestDigest`. The committed-state reader
requires `expected_structure_manifest_digest` at construction; there is no
seven-field or optional-pin fallback. This is a required, breaking source
contract, not evidence that the new checks have run.

The fixed child environment excludes ambient connection settings. Root delivery
and cold startup hash the signed TLS originals; ongoing checks retain exact
path/file metadata continuity rather than repeatedly hashing their contents.
These checks do not protect against a malicious root or a later privileged
replacement after an observation.

## Fixed raw2 request and raw4 response

[`authority_registration_completion_transport.py`](../serverware/authority_registration_completion_transport.py)
uses request magic `SWRCMP01` and response magic `SWRCMR01`. Each frame contains
the eight-byte magic, one big-endian u64 length for each body, then the bodies
in order and exact EOF. The client half-closes after its request.

The request has exactly two bodies:

1. Exact ASCII `recover-registration-evidence-completion`.
2. The canonical ASCII `sha256:` packet ID, exactly 71 bytes.

The request body total is 111 bytes. A fixed endpoint tuple contains the exact
completion socket path, timeout 1–30 seconds and listener UID/GID `0:0`. One
inherited absolute deadline covers connect, peer admission, framing, half-close
and EOF. All lengths are checked before body allocation. No parser, caller
callback, new work allowance, fallback endpoint or retry is provided here.

The response has four bodies: state, completion-request digest bytes, original
completion request bytes and original state receipt bytes:

| State | Digest | Request and receipt |
| --- | --- | --- |
| `acknowledged` | Canonical ASCII `sha256:` ID, 71 bytes | Original request 2 bytes–256 KiB; original receipt 2 bytes–16 KiB |
| `uncertain` | Empty | Both empty |

The ceilings come from the existing current-root delivery record contract.
No exception text is returned. Framing and the state label are not signature
verification: a consumer must authenticate both original signed controls and
their independent scope. A completion acknowledgment is not credential
finalization or an independently current state lease.

## Genuine readback and retained-original reuse

The existing
[`recover_and_deliver`](../serverware/authority_successor_completion_recovery.py)
composition uses actual `SuccessorExecutionRecoveryReader`,
`CurrentRootCommitReader`, `CurrentRootCompletionDelivery` and
`CurrentRootDecisionClient` owners. Custody recovery retrieves the original
packet through its fixed protected read function and independently pinned
selectors, with the recovery reader's genuine before/after catalog checks.
Returned originals still require historical authentication and replay.

When no completion is retained, genuine replay derives the expected marker and
full after-vector. The committed-state reader observes both under its existing
fixed read-only transaction and TLS/role/ACL checks. Its PID-bound owner checks
the full structural catalog against the independently pinned manifest before
and after the observer, on the same physical connection and unchanged work
allowance. Exact equality and normal database closure precede signing the
complete control. Catalog equality does not establish database provenance or
latest-root currentness. Per-host libpq and per-statement bounds plus outer
lifetime checks are not a hard driver or kernel-call watchdog.

The exact signed completion request is durable before its state exchange; the
authenticated original state acknowledgment is durable before a delivered
result is returned. If a matching completion is already retained, recovery
authenticates and reuses those unchanged bytes instead of producing a replacement
signature. An already acknowledged original can return its same retained
receipt without another state exchange.

A new read-only completion may follow execution-grant expiry, but it does not
renew execution authority. An unchanged expired completion can recover a receipt
only if the state owner already accepted it; an expired never-accepted original
is not replaced or renewed. Explicit recovery across independently admitted
cold launches cannot re-execute SQL, clear attempts or manufacture currentness
from historical receipts. Uncertainty permits none of those actions.

## Source packaging and remaining boundaries

The source chain is the
[`bootstrap`](../serverware/registration_execution_completion_bootstrap.py),
[`root entrypoint`](../serverware/registration_execution_completion_entrypoint.py),
[`startup owner`](../serverware/registration_execution_completion_startup.py),
[`runner`](../serverware/registration_execution_completion_runner.py) and
[`fixed launcher`](../serverware/registration_execution_completion_launcher.py).
The runner calls `initialize_from_environment()`, `require_started()` and
`close()`. The actual owner's `serve_once()` returns `False` only while idle,
`True` after one completed connection; an exception ends the launch. Its
`_recover_on_work` returns acknowledged raw4 only after joining the recovery
result's ID to the actual same-pending retained completion original. Ordinary
recovery failures return uncertain-empty; cancellation is not converted into
an acknowledgment or rollback claim.
[`Dockerfile.production`](../Dockerfile.production) copies the launcher and the
uninstalled [socket](../ops/systemd/serverware-registration-execution-completion.socket)
and [service template](../ops/systemd/serverware-registration-execution-completion.service.in).
It changes no entrypoint and activates nothing.

The template needs reviewed literal substitutions for `COMPLETION_RELEASE_ROOT`,
`COMPLETION_TRUST_DIR`, `COMPLETION_KEY_FILE`, `COMPLETION_TLS_DIR` and
`COMPLETION_JOURNAL_DIR`. `Restart=no` and the one-start limit prohibit automatic
service restart. AF_UNIX/AF_INET/AF_INET6 permit the required transport types,
not independent network authorization; PostgreSQL egress must be restricted
separately. UID65515 also needs independently provisioned access to the state
socket, whose `65516:65516` mode `0660` is not made accessible by a bind mount.

No accounts, keys, database privileges, trust history, current checkpoints,
socket ACLs, Compose wiring or public caller are provisioned here. Runtime
limits and cgroup termination are not hard watchdogs or rollback evidence.
Credential finalization and authenticated workload/session activation remain
separate operations with their own authorities and original-evidence joins.

## Deferred frozen verification

After source freeze and prerequisite admission, planned coverage includes:

- Root/configuration, fixed path, FD, key, TLS and environment rejection before
  resource use; wrong peer, purpose, packet pin, lengths or trailing bytes.
- Required exact structure-pin admission for both readers: reject seven-field,
  missing, malformed or mismatched pins and creator-PID drift; reject structural
  catalog drift before or after the same-connection committed-state observer.
- Genuine committed marker/full-vector readback, original replay and bounded
  signed completion, with no SQL executor invocation.
- Request durability before exchange and acknowledgment durability before reply;
  exact retained-original reuse after an independently admitted cold restart.
- Already accepted expired-original receipt recovery versus denial of an expired
  never-accepted original; no replacement signature or lifetime renewal.
- One accepted connection, exact raw4 outcomes, late expiry and uncertainty
  without automatic request/process retry or finalization.

This is planned coverage only; no tests or runtime verification have run for
this source batch.
