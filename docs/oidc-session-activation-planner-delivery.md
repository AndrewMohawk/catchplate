# Cold activation-planner delivery

This is unbuilt, unexecuted source packaging, not a provisioned service or a
completed authentication flow. The private planner prepares and retains signed
originals; it does not execute SQL, activate a session or release a browser token.

## Fixed custody boundary

The root entrypoint authenticates the original
[bootstrap](oidc-session-activation-planner-bootstrap.md) and actual activated
listener identities before opening private keys, TLS originals or the journal.
It opens only source-fixed paths through protected, nonsymlink root ancestors.
Bounded originals are sealed in memfds; private source files must be root-owned,
single-link, mode `0400`. The two encryption-key files contain exactly 32 raw
bytes, not encoded text. Their actual hashes must match the independently signed
pins, and the two keys must differ. The actual Ed25519 key pair and SPKI join the
dedicated planner public identity before the permanent privilege drop.

| FD | Fixed input |
| --- | --- |
| 198 | Independent root public key |
| 199 | Original root-signed bootstrap |
| 200 | Activated Unix stream listener |
| 201 | Dedicated planner signing key |
| 202 | Delivery encryption key |
| 203 | Separate private-journal encryption key |
| 204 | Independently pinned journal directory |

Only these seven descriptors survive as nonstandard descriptors. The process
drops permanently to UID/GID `65507` with no supplementary groups, and the
isolated launcher accepts only its fixed `/runtime/python` interpreter and
protected installed source directories. The replacement environment is literal:
ambient libpq configuration, arbitrary Python paths and caller-selected modules
cannot amend it. This is a trusted-host-local boundary, not protection against a
host administrator, hostile kernel or compromised installed release.

The listener is `/run/serverware/oidc-session-activation/planner.sock`; its
filesystem node must be owned by `65507:65532`, mode `0660`. The peer is the
separately admitted control-plane UID/GID `65532`. Kernel socket identity and
filesystem socket identity are distinct signed pins. The journal is the exact
`/var/lib/serverware/oidc-session-activation-planner` directory, owned by
`65507:65507`, mode `0700`, with signed device/inode/count/quota expectations.
The launcher never creates or repairs these resources.

Three fixed PostgreSQL TLS paths live below
`/run/serverware/oidc-session-activation-planner-tls`: `ca.pem`, `client.crt` and
`client.key`. Public files are root-owned mode `0444`; the private TLS key is
root-owned mode `0440`, group `65507`, so the already dropped libpq client can
open it. Actual content hashes are checked at cold admission; protected pathname
and metadata continuity are checked afterward. These cooperative local checks
do not defeat a malicious root writer or replace authenticated TLS/database
identity admission.

The fixed cold filesystem/TLS inventory checks have explicit file/count limits;
they are not claimed as metered semantic-proof work. Genuine bootstrap/key
verification spends the supplied cold work allowance, and original launch
freshness brackets delivery. Request proof work uses its own single bounded
invocation allowance, never a renewed allowance within that request.

## One request, no automatic restart

The runner permits idle listener polling but exits after the first accepted
connection, including a rejected or uncertain exchange. It does not retry
planning, mint a replacement token, re-sign a lost response or clear a retained
original. Root bootstrap lifetime, processing work and epoch/monotonic deadlines
remain bounded; local checks do not interrupt a blocked native or kernel call.

The unrendered
[service](../ops/systemd/serverware-oidc-session-activation-planner.service.in)
and [socket](../ops/systemd/serverware-oidc-session-activation-planner.socket)
templates require independent accounts, exact release, keys, signed bootstrap,
TLS identity, database privileges, journal and resource identities. The planner
template requires the separately admitted state socket and makes only its
socket directory visible inside the release root via a read-only bind; it does
not mount the state journal, trust directory or signing key. They are not
installed or started by this work. The service has no automatic restart and
limits starts to one; the operator must deliberately admit any later launch.
`Type=exec`, a socket connection or a process exit is not a readiness or durability
receipt. A response failure may follow successful local encrypted retention.

The production image recipe copies the fixed launcher from its verified source
stage. Both explicit frozen-source inventories include the bootstrap, cold
planning helper, transport, service and delivery modules. No image was built.

## Remaining authority

The v2 root bootstrap authenticates the supplied planning snapshot and exact
state enrollment/endpoint. The cold request now makes a fresh nonce-bound
[head observation](authority-current-root-head.md) through the explicit state-v4
planner-only purpose, rejects pending or mismatched state, and retains those
originals in the v2 plan/journal. This observes the independently admitted local
owner; it is not an off-host rollback witness or atomic action authorization.
The state socket still needs an independently provisioned narrowly scoped ACL
for UID65507; no supplemental state group or broad mutation access is added.
Separate public permission and retained-finalization ownership, one-use protected
SQL, committed delivery/recovery and the integrated portal remain open. No production gate is
closed by this source packaging.
