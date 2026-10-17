# Private consume SQL service

`oidc_session_activation_delivery_execution_sql_startup.py` connects the actual
consume SQL receiver, protected issuer/executor and durable attempt owner. This
is source integration, not evidence that a service is installed, provisioned,
built, tested or running. See the [root bootstrap](oidc-session-activation-delivery-execution-sql-bootstrap.md),
[OS delivery](oidc-session-activation-delivery-execution-sql-delivery.md) and
[raw8/raw4 protocol](oidc-session-activation-delivery-sql-transport.md).

## Cold ownership and lifetime

The fixed process is `oidc-session-activation-delivery-execution-sql`, UID/GID
65498, with empty supplementary groups and the literal eight-variable
environment. Its eleven inherited descriptors are root 198, role bootstrap 199,
listener 200, receiving custody 201, consume planner bootstrap 202, planning
history custody 203, SQL receiving history custody 204, execution-bundle AES key
205, historical-bundle AES key 206, delivery AES key 207 and attempt directory
208. There is no signing key. The listener is
`/run/catchplate/oidc-session-activation-delivery-execution/sql.sock`; peer
UID/GID 65532 is required before request bodies are read.

The root launcher opens the actual construction work/window before protected
root/key I/O. After permanent privilege drop it continues in the same isolated
PID through the mandatory
`initialize_from_environment(work=..., live_window=..., transport_deadline_ns=...)`.
There is no post-drop exec, standalone worker renewal or accepted material DTO.
Startup reauthenticates the five signed/detached originals and independently
held root before constructing `for_sql_issuer` custody from the three admitted
AES keys. A grant or reserve custody purpose cannot substitute.

One cumulative startup ledger covers the root continuation, original admission,
key reads, fixed TLS hashes and attempt recovery. Charging helpers are called
directly: their native callbacks do not themselves charge the ledger. Attempt
recovery likewise directly invokes the real journal consumer, retaining its
per-record and surrounding original-clock guards; it is not enclosed in a
metrics-constant callback. Legacy default recovery and attempt claims are
unchanged.

The actual attempt directory is independently reopened/locked under signed
device/inode, owner, quota and checkpoint pins. Actual `SuccessorExecutionIssuer`
and `SuccessorExecutionExecutor` owners use the independently admitted eight-field
configurations and fixed five TLS originals. PID, environment, immutable
configuration, sealed descriptors, listener/directory identities, TLS metadata
and attempt ownership remain guarded. The original startup bracket/deadline
survives idle time and the entire accepted exchange; a later role freshness
sample does not replace it.

## Actual protected exchange

The launch is spent as soon as one connection is accepted, even for a wrong peer,
malformed frame, expired authority or uncertain outcome. A separate request
work/window opens before peer/body intake and is capped by the inherited startup
lifetime. Canonical closed consume expectations can only narrow it. All original
role inputs are reauthenticated for the request.

The service supplies the genuine bridge with exact raw2 plan/ciphertext, caller
authorization, grant, reserve/snapshot/ACK and independently root-held before
vector, predecessor, database/generation, current pending sequence/head and
fence. An ACK never supplies its own expected pending authority. The dedicated
issuer path performs actual consume original replay and pending admission once,
then publishes its protected packet. Only that call's actual returned IDs reach
the executor, which uses the durable one-use attempt owner. Startup does not
pre-replay and then replay again, or use a generic consume dispatch fallback.

A normal response is an unsigned `observed-commit` with those IDs and the bounded
actual marker. Uncertainty is sent only from the genuine same-call typed outcome
continuation: its original window, deadline and live guard must all exist and
remain valid. Both result paths preserve the original opening, intersect the
remaining grant/reserve/packet lifetime, and run the actual guard before and
after serialization, sending and accepted-socket cleanup. Missing or expired
continuation means connection closure without an invented response or IDs.

The runner closes actual custody, the attempt owner/journal, listener duplicate
and all eleven inherited descriptors. Acquisition keeps resource ownership
before a later callback suffix can fail. Cleanup never clears a durable attempt,
reissues a packet or retries SQL. Neither response establishes signed completion,
committed-original release authority, a browser token, public permission or
current authentication. Those downstream recovery/release boundaries remain
separate.
