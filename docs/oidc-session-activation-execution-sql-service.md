# Dedicated activation SQL service

`oidc_session_activation_execution_sql_startup` connects original activation
authority and independently admitted pending state to the actual protected
issuer/executor owners. Its fixed APIs are `initialize_from_environment()`,
`require_started().serve_once()` and `close()`. This is source-only: unbuilt,
unexecuted, unprovisioned and not production verification.

The dedicated process is UID/GID 65504 with request peer 65532. Root-signed
[bootstrap admission](oidc-session-activation-execution-sql-bootstrap.md)
precedes AES key loading, TLS-file admission and journal/owner construction.
The exact seven inherited descriptors are root 198, bootstrap 199, listener
200, receiving-custody original 201, bundle key 202, delivery key 203 and attempt
journal 204. There is no authority signing key or completion key.

The actual receiving owner is fixed to `sql-issuer`; neither a grant nor reserve
owner substitutes. Its independent root/configuration/key/policy and original
planner/state inputs are genuinely reauthenticated. Original request bytes do
not select roots, keys, SQL roles, TLS paths, checkpoints or expected pending
state. The protected packet contains ciphertext originals, never plaintext
private journal tokens or AES keys.

## Connected original path

One request work/window opens before peer, prefix or body intake. The fixed
[raw8 request](oidc-session-activation-sql-transport.md) is authorization, signed plan, encrypted bundle, canonical closed
expectations, grant, reserve request, snapshot and ACK. Incoming scope only
narrows that clock bracket. The service reauthenticates original role/custody
bytes and passes root-admitted predecessor, independently **current** pending
sequence/head/fence, database/generation and configured keys to the actual
activation [SQL bridge](oidc-session-activation-sql.md).

The bridge calls genuine original pending admission, then the real issuer,
which again replays original inputs within the remaining same allowance.
Only the actual issuer's returned custody identities reach the real executor.
It burns the durable attempt before opening its execution SQL connection; timeout, abort,
uncertain delivery and identical resubmission cannot clear it or earn a retry.
No received successful DTO or caller-supplied packet locator authorizes work.

The two actual database owners keep independent fixed-role/TLS identity and
query/catalog provenance. Equal catalog digests do not prove database identity.
The service validates their exact original eight-field configurations and the
executor's actual attempt owner throughout its lifetime; the real SQL owners
retain their own protected database/transaction checks.

The actual same-call successful result retains original admission liveness and
the narrowest issuer/reserve/grant/caller/plan expiry. The service preserves its
original opening samples, clips response transmission to that deadline and
calls the real liveness check before and after sending. The raw4 response is
an **unsigned observed commit**, not signed completion, token delivery or an
active browser session. When failure produces a response, it contains only
static unsigned uncertainty, with real same-call custody identities when
available and no fabricated IDs, exception details, noncommit claim or retry
permission. Other failures can close without a response and remain uncertain.

## Custody, attempts and cleanup

The separate private 0700 attempt directory is
`/var/lib/catchplate/oidc-session-activation-execution-sql-attempts`. Its exact
device/inode and independently current local checkpoint come from root
admission, not recovered records or a database receipt. The actual journal
owns an independent open/flock and immutable bounded records.

`SuccessorExecutionAttempts` now optionally accepts the complete inherited
`live_window`, `work` and `transport_deadline_ns` trio. This activation owner
uses it for cumulative cold genesis/recovery and final checks; supplying only
part is rejected. Existing all-omitted constructors retain their prior fixed
per-record cold budgets. Attempt claiming, one-use identities, checkpoint
comparison, poisoning and no-pruning semantics are unchanged.

The source-fixed TLS directory is
`/run/catchplate/oidc-session-activation-execution-sql-tls`: `ca.pem`,
`issuer.crt`, `issuer.key`, `executor.crt`, `executor.key`. Signed original
digest/size pins are checked at cold admission, then protected path/metadata
continuity is checked. Public files are root-owned 0444; private libpq files
are root:65504 mode 0440. These trusted-host-local checks are not hostile-root
protection, a fresh off-host witness or an external syscall watchdog.

PID/UID/GID, empty supplementary groups, literal environment, sealed originals,
listener/journal identities, TLS metadata, actual owners, exact descriptor
inventory and nonregressing epoch/monotonic samples remain guarded. Every
accepted connection spends the launch, including malformed input or failure.
Allocated journal/attempt resources are held before callback-suffix checks can
fail. Cleanup closes the accepted and duplicate listener, attempt/journal
owner, private receiving owner and all seven adopted inherited descriptors.

This connects the previously separate current-pending consumer; it does not
complete/reconcile activation, release a token, add public permissions/routes,
activate a portal session or provision deployment dependencies. Those remain
explicit separate boundaries.
