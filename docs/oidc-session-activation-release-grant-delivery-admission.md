# Independent admission of an issued release bootstrap

The dynamic receiver verifies the exact incoming signed server-bootstrap bytes
against its independently held root, issuer policy and policy-pinned proof-worker
bootstrap. An incoming bootstrap, issuer acknowledgement or material-shaped
object cannot supply those independent expectations.

`_verify_on_work(server_bootstrap_bytes=..., issuer_policy_bytes=...,
proof_bootstrap_bytes=..., root_public_key=..., live_window=...,
transport_deadline_ns=..., work=...)` performs genuine policy/proof admission,
then genuine server-bootstrap, custody and storage-authorization admission.
It joins the exact custody original, entire authorized launch, expected release,
configuration/database/generation/runtime and producer/receiver identities,
caller, original completion receipt and LIVE zero/null checkpoint. Recovery
bootstraps are not accepted on this path.

The server's interval must fit inside the independent issuer policy and proof
bootstrap. Both actual original guards remain live under the same cumulative
work, epoch/monotonic floors and only-narrowing original window/deadline. The
optional continuity hook supplies only restrictive clock floors, not authority.
Only existing private lifetime bookkeeping is reused from the issuer producer;
no root private key or signing operation is used by receiving admission.

The returned immutable material contains the exact admitted bytes, actual
same-call server and policy materials, framed bootstrap identity and retained
live guard. It is an output, never an alternative input to original admission.
Encoded and decoded original inventories are bounded by the same 64 MiB ceiling.

This library observes no filesystem, listener, private key or storage contents.
Signed resource pins and a zero-record authorization are expectations, not
observations. The [dynamic root delivery](oidc-session-activation-release-dynamic-delivery.md)
must independently stage and validate actual resources before acknowledging the
exact original. Even that acknowledgement establishes no privilege-drop success,
worker readiness, returned token, current session or production acceptance.

Source only: unbuilt and unexecuted. Independent key/resource provisioning,
consume-input acquisition, per-request proof provisioning and the public
HTTP/current-auth/cookie flow remain required.
