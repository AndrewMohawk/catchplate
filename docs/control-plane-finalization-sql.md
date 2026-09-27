# Private finalization SQL caller

This source-only caller connects the independently root-admitted finalization
pending scope to the [dedicated cold SQL worker](registration-finalization-sql-service.md).
It is unbuilt, unexecuted and unprovisioned. The separately authorized
[public execute action](public-registration-finalization-sql.md) and seventh
portal control now use the retained facade; neither supplies signed completion
or OIDC activation.

The actual enrollment owner exposes
`_request_registration_finalization_sql(*, local_digest, originals, live_window,
transport_deadline_ns, work)` under its existing PID and owner lock.
Only the explicit nested-v3 profile supplies the fixed SQL endpoint and
independently signed current pending sequence/head/fence. V1/v2 do not acquire
SQL dispatch. The configured key/custody/lifetime remains held throughout.

Before this private method, the actual application must separately admit the
present finalization-execution purpose and retained subject ownership. The
existing reservation permission does not authorize SQL. The
[retained facade](../serverware/control_plane_registration_finalization_handoff.py)
repeats actual finalization/signer/evidence-completion replay and user/session
ownership under the cold owner lock. The private method also requires the
actual finalization grant `local_digest` and rejoins raw13 to that complete
retained association; it is not an alternate public bypass.

## One original-bound request

The [caller implementation](../serverware/control_plane_registration_finalization_sql.py)
holds raw13: finalization grant raw10 followed by original reserve/snapshot/
acknowledgment raw3. Genuine [original admission](registration-finalization-sql-admission.md)
checks caller, plan, grant, full vectors, snapshot and state receipt against the
independent pending pins before one [transport exchange](registration-finalization-sql-transport.md).
No received head supplies the expected current head.

After genuine pending admission, the caller atomically publishes its durable
[local dispatch claim](control-plane-custody-journal.md#finalization-sql-attempt-and-outcome)
before transport can send. It durably retains a bounded returned unsigned raw4
before semantic or invocation-lifetime acceptance. This ordering preserves
uncertainty and mismatching or late outcomes as opaque originals, not verified
success. A failed send, missing response or failed acceptance never clears the
claim; the remote executor's protected attempt is a separate one-use boundary.

One caller work/window covers admission, transport and return. The endpoint cap
starts at that original window's monotonic opening, not after replay. Original
grant/reserve expiry, inherited deadline, actual owner/configuration/key/custody
continuity and clock rollback checks remain live before and after the exchange.
Raw13, raw4 and the three enrollment originals together stay within 64 MiB.
Nothing opens a replacement authorization window or signs new permission.

## Returned observations stay bounded

The caller accepts only the transport's closed unsigned raw4 carrier. Whenever
the service reports custody IDs, the pending-decision ID must equal the
independently supplied pending head. The packet ID is a reported locator, not
independently proven packet provenance. An uncertain response may omit both
IDs; that absence does not prove noncommit or allow retry.

For `observed-commit`, the actual source marker parser checks canonical bounded
ASCII and the exact eighteen-column marker contract. Every field is then
compared with `marker_expectation`, derived by the actual pending helper from
the same invocation's genuinely verified enrollment/request/receipt/snapshot.
No caller-supplied marker or successful verification object enters that
expectation. A matching marker remains an unsigned local commit observation;
the independently owned signed completion path is still required.

The private method returns unchanged raw4 only after its final original-lifetime
checks. The facade returns `(local grant ID, raw4)` only for `observed-commit`;
uncertainty is an error, not HTTP success. Public projection exposes no raw
marker or custody IDs and keeps completion/session/currentness flags false.
It does not clear an attempt, reset a journal, reconnect, retry SQL, activate a
session or infer rollback from failure. A timeout or late failure can follow
remote issuance, a durable one-use attempt or a committed credential mutation.

Static root-signed scope and protected local storage do not establish live
off-host currentness or resist hostile-root rollback. Independent provisioning,
action-time authority and the full production verification gates remain open.
Finalization completion/recovery and its independently authorized session
activation remain separate work; the evidence-recovery action is not their substitute.
