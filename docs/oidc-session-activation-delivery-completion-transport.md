# Private consume completion transport

[`authority_oidc_session_activation_delivery_completion_transport.py`](../serverware/authority_oidc_session_activation_delivery_completion_transport.py)
frames one private completion recovery request and an unverified original
response. It does not decode proofs, admit completion, renew execution permission
or establish currentness.

The only socket is
`/run/serverware/oidc-session-activation-delivery-execution/completion.sock`, for
process `oidc-session-activation-delivery-completion`, UID/GID 65497. The server
admits request peer **65497:65497**, a separately root-admitted completion-purpose
receiver, before any prefix or body. This does not give generic application UID
65532 AES keys or private recovery authority. Clients require the inherited
root-created listener's kernel peer **0:0** before sending. Filesystem access,
process admission and actual original verification remain separate gates.

The source-fixed request magic is `SWODCM01`; response magic is `SWODCR01`.
An eight-byte magic is followed by big-endian eight-byte lengths, then exact
original byte frames:

| Direction | Exact inventory |
| --- | --- |
| Request raw2 | `recover-oidc-session-activation-delivery-completion`, canonical 71-byte packet digest |
| Acknowledged raw4 | `acknowledged`, canonical completion-request digest, original signed complete control, original state ACK |
| Uncertain raw4 | `uncertain`, three empty frames |

Both fixed headers and the maximum request/response bodies must fit the 64 MiB
whole-exchange ceiling before any body allocation. Each field retains its actual
completion-record cap. Exact EOF rejects trailing bytes; the client half-closes
after the request and the service closes after its sole response. No alternate
endpoint, operation, old-format fallback, automatic resend or retry is provided.

`_recv_request(connection, deadline_ns=...)` returns raw2;
`_send_response(connection, originals, deadline_ns=...)` sends raw4;
`_socket_request(endpoint, originals=..., deadline_ns=...)` returns unverified
raw4. `_originals(values, response=...)` performs only closed byte framing. Every
exchange requires a positive inherited absolute monotonic deadline; endpoint
timeout may only shorten it. The transport creates no work ledger or authority
window. The caller/service meters bytes on its existing allowance and retains
genuine custody/liveness guards around I/O.

An `acknowledged` label or matching digest is not completion authority. The
consumer must genuinely verify the returned signed complete/state originals
against independently held original plan/control, pending, configuration and
enrollment scope. The packet digest selects the request only: raw4 contains no
packet identity and cannot itself prove that returned packet association.
`uncertain`, EOF or an exception does not prove rollback, SQL noncommit or
that no durable completion exists. There is no permission to replace, resign or
repeat SQL. The [state v9 peer](current-root-delivery-completion-peer.md) separately
restricts state complete/known-original lookup to the consume operation.

This is source-only, unbuilt, unexecuted and uninstalled. Cold caller/public
handoff packaging and production provisioning are separate work; no plaintext
token release or current-session claim is made here.
