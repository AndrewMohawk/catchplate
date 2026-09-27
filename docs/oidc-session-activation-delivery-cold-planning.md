# Private consume-planner lifecycle

`authority_oidc_session_activation_delivery_cold_planning._create_on_work`
authenticates the [root bootstrap](oidc-session-activation-delivery-planner-bootstrap.md)
and nested history originals itself. It constructs the actual read planner,
UID 65501 history custodian, independent encrypted
[original journal](oidc-session-activation-delivery-journal.md), and retained
[plan owner](oidc-session-activation-delivery-plan-owner.md). No received material,
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
- `close`: closes the retained owner/journal and then its history custodian.

Each operation reauthenticates root originals and exact held owner/key/journal
configuration before and after its actual work. Original launch opening and
current history guards survive through final return. Processing only narrows
the supplied first clock bracket; no replacement work/window or historical
execution allowance is created. The read planner's configured skew remains an
exact profile match; an incompatible stricter caller is rejected, not reset.

Construction checks the real signer pair, three distinct exact32 AES keys and
their root digests. The actual FD 206 directory and fixed protected pathname
must match root-admitted device/inode, UID/GID 65501 and mode 0700. Fixed TLS
files require protected root ancestors, no symlink, exact original SHA/size,
root ownership, public mode 0444 or private root:65501 mode 0440. Reads and
hashing debit the same work; path/file metadata continuity is checked around
calls. Journal leases, bounded recovery and poisoning belong to the real store.

The factory is source-connected to the retained owner's required journal,
append-before-return `journal_digest`, known-envelope `verify_retained`, and
journal-owning close. The fresh head's scope deadline is the same original
outer/history-narrowed deadline used by actual prepare. Retained verification
uses the independently supplied original deadline, and post-owner checks keep
the original signed plan expiry live through the wrapper's final return.

This slice declares future FDs but does not deliver sealed keys, launch/listen,
install a service, or provision DB/TLS/state-socket access. It is not a runnable
or deployed cold service claim. No automatic retry, fresh public
consent, issuance/reservation/one-use SQL/recovery, token release, or production
verification is supplied. Expired consume plans are never accepted as live.
