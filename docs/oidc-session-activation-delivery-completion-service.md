# Dedicated consume completion service

This is connected, source-only cold composition of the dedicated
[completion recovery](oidc-session-activation-delivery-completion-recovery.md)
library. It is unbuilt, unexecuted and uninstalled. It does not release a token,
establish a current session, retry SQL or supply public permission.

The fixed launcher admits only `--root-delivery`. The
[root bootstrap and delivery](oidc-session-activation-delivery-completion-bootstrap.md)
authenticate the role, embedded original custody controls and independently
pinned resources before private key I/O. Root permanently drops to UID/GID
65497 with empty supplementary groups, installs the literal eight-variable
environment, and directly invokes the runner in the same PID. The runner's
mandatory `work`, `live_window` and `transport_deadline_ns` are the actual
construction objects opened before root I/O, not serialized substitutes.
Standalone `--run`, post-drop exec and renewed startup allowances are absent.

## Fixed resources and genuine recovery

Descriptors 198–205 are exactly root, role bootstrap, listener, completion
signer, completion journal, consume execution AES key, historical activation
AES key and delivery AES key. They retain CLOEXEC. The 32 MiB role-original cap
covers the four embedded custody originals. Startup independently reauthenticates
the original role, checks the signed listener/journal identities and sealed
originals, and constructs the actual completion-purpose custody owner with
all three independently pinned keys. No received material or result object
stands in for original admission.

The real packet and commit readers use the independently root-admitted database
roles, endpoint, TLS identities, query and catalog pins. The current-root
enrollment pins the completion signer and bounds current processing. Independent
pending sequence/head/fence and the packet digest come from the signed role,
not a state acknowledgment or the request selector. The local completion
checkpoint is separately pinned; it is not current-root authority.

The real completion journal restores exact records under the inherited
construction allowance. Its optional inherited-work read seam charges each
validated declared record size before allocation/native read/hash; semantic
reducers run outside the metrics-stable native callback and charge the same
work. Existing callers without inherited work retain their prior API. Journal
recovery is not a per-record budget reset.

The service invokes actual dedicated `recover_and_deliver` once. First
completion requires original replay and the real immutable commit observation,
then retains the exact signed completion before state transport. Recovery
authenticates the stored originals and performs genuine state reconciliation;
it never replaces them or repeats SQL. The response carries the actual durable
completion and actual retained state acknowledgment, joined to this invocation's
result. The server does not replay its own response as independent receiving
verification.

## One root-selected exchange, one bounded lifetime

The listener is
`/run/serverware/oidc-session-activation-delivery-execution/completion.sock`.
Launch v1 retains owner/group 65497:65497, mode 0660 and only peer
65497:65497: a separately root-admitted, same-purpose private receiving process
can use the actual custody-aware response client. Distinct root-signed launch
v2 requires owner/group 65497:65532, the same mode and only control-plane peer
65532:65532. The service UID stays 65497. Its lifecycle seal retains the selected
schema, and listener checks derive one exact ACL from that schema; no peer-OR
fallback is accepted. The opt-in socket drop-in must match the admitted v2
bootstrap. Neither profile gives the application AES/history access. A client
pin of root 0:0 identifies the inherited root-created socket endpoint, not an
attestation of the serving UID.

The [fixed transport](oidc-session-activation-delivery-completion-transport.md)
retains v1's recovery purpose and independently expected packet digest. V2
selects the separate dispatch transport before peer/header/body intake:
`SWODCM02`, fixed purpose `complete-oidc-session-activation-delivery`, and the
exact signed consume caller authorization original. The actual peer must match
the selected profile. After genuine root bootstrap re-admission, the service
compares that authorization byte-for-byte with `material.authorization_bytes`.
It never derives packet or pending scope from the caller or SQL response; both
profiles use only the server's independent root pins for actual recovery.
Old v1 wire/schema/peer acceptance stays strict, with no fallback. Both profiles
return the existing `SWODCR01` raw4 acknowledged/uncertain grammar, not a packet
identifier or authenticated current-session claim.

One request allowance opens before peer/prefix/body intake and is capped by the
original startup allowance. Original role and custody lifetimes and the minimum
enrolled control/caller/planner age and skew can only narrow it; old historical
consume deadlines never become current clock samples or renewed authority.
The wire checks reserve the whole bounded exchange before body allocation;
the service additionally meters request and response framing on its work.

Actual custody, current clocks, sealed originals, reader configurations, TLS,
listener/journal identities and descriptor inventory remain checked across
recovery, serialization and sending. Even the closed `uncertain` response
requires a genuine still-live custody guard. Expiry, exhausted work, poisoned
journal or lost resource continuity emits no such response. An uncertain result
does not assert noncommit, authorize retry or clear durable originals.

Exactly one accepted connection spends the launch, including malformed or
rejected peers. Idle waits remain inside the launch; no automatic retry or
restart is installed. Cleanup closes the owned listener/journal/custody and all
eight inherited descriptors without deleting durable records.

The source units require independent account, key, TLS, database, checkpoint,
journal, socket-DAC and state-v9 provisioning. They create none of those trust
facts and are not installed or started by this change. V2's explicit dispatch
connection does not itself close the public activation route or authorize token
release. Their isolation claim is
trusted-host-local, not TEE, off-host attestation or production verification.
