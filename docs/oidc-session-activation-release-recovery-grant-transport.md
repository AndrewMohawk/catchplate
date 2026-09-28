# Recovery grant transport

`authority_oidc_session_activation_release_recovery_grant_transport.py` defines
only a fixed private framing profile. It accepts no configurable codec, resource
path, issuer policy or root authority in request data. LIVE grant framing is
unchanged.

The endpoint is `/run/serverware/oidc-session-activation-token-release/recovery-grants.sock`,
timeout 1–30 seconds, with root listener peer UID/GID 0:0. The service admits only
caller UID/GID 65532:65532 before reading request bytes. Request/response magics
are `SWORGQ01` / `SWORGR01`.

The request raw8 is the fixed issuer purpose
`issue-oidc-session-activation-release-recovery-grants`, followed by the existing
recovery prefix7: recovery purpose, signed proof, proof enrollment, signed
intent, intent enrollment, ephemeral old-token64, encrypted envelope100. There
is no candidate outcome or issuer authority in that request. Exact frame bounds
come from the existing recovery grammar. The response raw3 contains immutable
client authorization (2 bytes–16 KiB), server bootstrap (2 bytes–16 MiB) and
canonical outcome (2 bytes–64 KiB). Framing authenticates none of them. There is
no status/error response or token-response frame.

`_recv_request(connection, *, deadline_ns, work, current,
maximum_request_bytes=None)` checks the exact peer, magic, every fixed length
and optional tightening body-total cap before allocation, precharges the whole
request, and requires exact EOF. `_send_response(connection, originals, *,
deadline_ns, work, current)` bounds and precharges all frames. Both retain the
server's accepted-socket ownership and original guard through native chunks;
neither closes, detaches or transfers the connection.

`_socket_request_on_work(endpoint, *, originals, deadline_ns, work, current,
maximum_response_bytes=None)` invokes the fifteenth source-fixed guarded caller
profile. Its optional cap only tightens the total response size (at least six
bytes); headers and all lengths are checked before body allocation. The shared
caller checks the root peer before sending originals, preserves the inherited
ledger/epoch floors/absolute deadline, requires response EOF, and attempts its
owned socket close once. A failed send, read, guard or close suppresses the
result; there is no reconnect, repeated close, automatic retry or new allowance.
The whole framed exchange remains bounded by 64 MiB.

The original-only [caller](control-plane-oidc-session-activation-release-recovery-grant-acquisition.md)
genuinely admits independent policy before contact and the returned triple
afterward. This transport itself supplies no public permission, durable attempt
claim, storage observation, release-worker staging or token opening. No service
installation, execution or readiness is claimed.
