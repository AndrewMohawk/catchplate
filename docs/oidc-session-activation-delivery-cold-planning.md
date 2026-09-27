# Private consume-planner lifecycle

`authority_oidc_session_activation_delivery_cold_planning._create_on_work`
authenticates the [root bootstrap](oidc-session-activation-delivery-planner-bootstrap.md)
and nested history originals itself. It constructs the actual read planner,
UID 65501 history custodian, independent encrypted
[original journal](oidc-session-activation-delivery-journal.md), and retained
[plan owner](oidc-session-activation-delivery-plan-owner.md), and separately keyed
[execution-ciphertext store](oidc-session-activation-delivery-execution-store.md). No received material,
successful read result, arbitrary callback or bare configured owner is an input
or output.

Its private process-bound `_ColdPlanner` owns a nonblocking lifecycle lock and
only exposes these fixed operations:

- `prepare`: immutable old-token possession and the original activation raw13,
  plus the existing work/window/deadline. Request, subject, policies and complete
  roots/heads come from independent signed bootstrap originals. After narrowing
  outer/history bounds, it makes a fresh nonce-bound fixed-purpose state query
  and calls the genuine acquisition, provenance, proof replay, signing and
  retention path. Return is the actual token-free prepared plan/locator only.
- `verify_retained`: known original envelope, independently expected original
  scope deadline and journal digest, plus current processing bounds. Fixed
  request/policy/root/head expectations still come from the root bootstrap. The
  retained owner authenticates the known signature before lookup and genuinely
  replays stored originals; stored roots are never adopted as independent pins.
- `export_retained`: the same independently bound original inputs, with genuine
  retained replay followed by [first-exact durable export](oidc-session-activation-delivery-execution-export.md).
  The actual exporter holds the retained-owner lock, reads before sealing and
  compares recovered plaintext with the exact originals verified in that call.
  Return is ordinary immutable request/scope/plan/digest metadata plus ciphertext,
  never plaintext, a key or receiving/execution authority. No second full replay
  is substituted for the export composition or triggered merely to form metadata.
- `close`: closes the retained owner/journal, execution store and history
  custodian, using nested cleanup so a failure does not skip the other owners.

Each operation reauthenticates root originals and exact held owner/key/journal/store
configuration before and after its actual work. Original launch opening and
current history guards survive through final return. Processing only narrows
the supplied first clock bracket; no replacement work/window or historical
execution allowance is created. The read planner's configured skew remains an
exact profile match; an incompatible stricter caller is rejected, not reset.

Construction checks the real signer pair, four distinct exact32 AES keys and
their root digests. Bootstrap v2 also separates the new export key from the
historical activation journal-key pin. The actual FD 206 journal and FD 208
execution store must each match their distinct fixed protected pathname and
root-admitted device/inode, UID/GID 65501 and mode 0700. Directory pins are also
separate from historical activation journal/export storage. Fixed TLS
files require protected root ancestors, no symlink, exact original SHA/size,
root ownership, public mode 0444 or private root:65501 mode 0440. Reads and
hashing debit the same work; path/file metadata continuity is checked around
calls. Independent journal/store leases, bounded recovery and poisoning belong
to the respective real owners; their configuration snapshots and quotas are
joined to the signed root originals before use.

The factory is source-connected to the retained owner's required journal,
append-before-return `journal_digest`, known-envelope `verify_retained`, and
journal-owning close. The fresh head's scope deadline is the same original
outer/history-narrowed deadline used by actual prepare. Retained verification
uses the independently supplied original deadline, and post-owner checks keep
the original signed plan expiry live through the wrapper's final return.

The `.162` [OS delivery](oidc-session-activation-delivery-planner-delivery.md)
and [private service](oidc-session-activation-delivery-planner-service.md)
connect all eleven fixed descriptors to this actual factory and its three operations.
They preserve the original construction lifetime through idle acceptance and a
single accepted exchange. This is unbuilt, unexecuted source, not an installed
service or provisioned DB/TLS/state-socket access. This closes sender-side export
composition only, not independently admitted receiving custody/full replay or
actual grant issuance. No automatic retry, fresh public consent,
reservation/one-use SQL/recovery, token release or
production verification is supplied. Expired consume plans are never live.
