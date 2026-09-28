# One-shot recovery grant issuer

This source-defined private service continues the genuine root delivery described
in [the cold-delivery guide](oidc-session-activation-release-recovery-issuer-delivery.md).
It issues one independently authorized recovery grant triple. It does not stage
a recovery worker, observe a durable outcome, open a token or complete recovery.
The existing LIVE release receiver remains unchanged and rejects recovery input.

## Original continuation

The isolated launcher accepts only `--root-delivery` at the fixed runtime path.
The root entrypoint authenticates the independent launch and policy originals
before reading the pinned root signer, then permanently drops the same process
to UID/GID 65493 with no supplementary groups. There is no post-drop exec.
The runner passes the same validation work, original clock window, tightened
deadline and actual source-owned delivery continuation to startup.

Startup reauthenticates the exact sealed originals and root key pair. It retains
the original ledger, maxima, PID, thread, closed environment and clock floors.
The signed request timeout is measured from the original window anchor, not
from accept or signing. Nested production exchanges restrictive clock floors;
it cannot introduce a new processing allowance or successful-result authority.

The inherited inventory is exactly eight descriptors:

| FD | Resource |
| --- | --- |
| 198 | Root public key |
| 199 | Signed issuer bootstrap |
| 200 | Root-created recovery-grants listener |
| 201 | Independent recovery issuer policy |
| 202 | Historical release custody original |
| 203 | Proof enrollment original |
| 204 | Intent enrollment original |
| 205 | Pinned root signing key |

No TLS, AES, completion signer, journal, SQL or outcome-store resource is opened
by this owner. Root-authorized resource pins in issued grants do not provision
or establish the existence of those resources.

## One terminal exchange

`serve_once()` spends its latch before readiness wait or accept. The sole
accepted nonblocking, non-inheritable Unix socket must have kernel peer
UID/GID 65532 before any request bytes are read. Startup admits only that exact
owned socket alongside the inherited inventory; there is no descriptor exemption.

The fixed socket is
`/run/serverware/oidc-session-activation-token-release/recovery-grants.sock`.
The [bounded protocol](oidc-session-activation-release-recovery-grant-transport.md)
receives its fixed issuer purpose followed by the seven original recovery
request frames. Only that suffix is passed to the
[original-only producer](oidc-session-activation-release-recovery-grant-production.md),
with the separately inherited policy, custody, enrollments and actual root pair.

Before body allocation, a tightening request cap reserves the simultaneously
held root-delivery material, reread originals, known decoded graphs, nested
producer copies, output/readback capacity and framing within 64 MiB. Per-frame
limits remain in force. Capacity helpers operate directly on the same ledger.
The producer's canonical outcome is reconstructed against independent signed
expectations; reconstruction is not evidence of a checkpoint-one store record.

The only response is the exact three originals: client authorization, recovery
server bootstrap and canonical outcome. The generated client expiry can only
tighten send and normal-close bounds. No token, exception text or alternate
success/error frame is returned. Failure, partial I/O and uncertain close are
terminal; no retry or replacement request is possible. Cleanup makes a sole
close attempt only for the actual owned identity, never a reused descriptor.

## Evidence boundary

The checked-in socket and service template are uninstalled source recipes.
They use the isolated launcher, eight descriptors and permanent UID/GID 65493
drop; they add no recovery-worker staging. This slice is unbuilt, unexecuted
and unprovisioned. Parent actor configuration, durable acquired originals,
recovery-worker staging, protected exchange and public recovery/cookie wiring
remain separate work. Issuance does not authorize a SQL retry or prove recovery.
