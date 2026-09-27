# Private first-exact consume ciphertext export

[`authority_oidc_session_activation_delivery_execution_export._export_on_work`](../serverware/authority_oidc_session_activation_delivery_execution_export.py)
connects the actual retained consume-plan owner to the dedicated
`DeliveryExecutionBundleStore`. It returns only the first exact durable
ciphertext. This source-only composition does not admit a received success
object, issue a grant, execute SQL, release a token or create a service.

```text
_export_on_work(owner, store, *, envelope_bytes, expected_request,
    expected_scope, business_before_roots, authorization_before_roots,
    expected_counted_heads, expected_journal_digest, bundle_key,
    live_window, transport_deadline_ns, work) -> first ciphertext bytes
```

The caller must independently authenticate the original cold configuration,
keys and resource pins. Inputs include actual exact-class owners, the known
signed consume envelope, independently expected request/scope/primary roots,
all seven counted heads and the original journal ciphertext digest. These
expectations are not learned from a lookup or successful producer result.

## Owner and original joins

The exporter retains the real nonblocking plan-owner lock throughout capture,
replay, storage and return. All caller graphs are detached before cryptographic,
clock or file callbacks. The store's stable six-field configuration joins the
owner's source/configuration and exact independently supplied 32-byte bundle
key. That new key must differ from the actual consume-journal key and both
historical activation bundle/delivery keys. The store and journal must have
different device/inode pairs and matching private UID/GID ownership. These
joins do not establish independent provenance by themselves.

The private `_verify_retained_locked` helper factors the genuine existing
[retained-owner path](oidc-session-activation-delivery-plan-owner.md). It
requires the caller-held actual lock/configuration, authenticates the known
plan signature before journal lookup, reads only the mandatory digest-bound
record and restores the exact canonical sixteen-field original document.
Independent request/scope, primary roots, seven heads, activation expectations,
state enrollment, complete vector, keys and history purpose are joined before
the actual full plan verifier runs once. Current state, old-token possession,
completed-activation provenance and indexed effects are genuinely replayed;
an authenticated stored document alone is insufficient.

The helper's ordinary private return contains original bytes, journal scope,
narrowed processing window/deadline, owner guard and the actual same-call full
replay. No public API accepts that tuple as authority. Public `verify_retained`
keeps its existing signature and unchanged five-field `PreparedDeliveryPlan`
result. Neither path reacquires a snapshot, signs another plan, regenerates a
missing record or accepts an expired consume plan.

## Read before seal, then exact durable bytes

The exporter derives the distinct seven-field
[consume bundle context](oidc-session-activation-delivery-execution-bundle.md)
from the admitted original scope and independently expected journal digest.
It checks the store's whole-record 64 MiB ceiling before sealing; the original
plan/ciphertext pair and cumulative supplied work remain bounded as well.
No enclosing transport or packet cap is enlarged.

It calls the actual store's `read` before creating a candidate:

- If a first ciphertext exists, it opens those exact bytes with the independent
  expected context and compares the canonical plaintext byte-for-byte to this
  call's freshly authenticated and replayed journal original. It returns the
  retained ciphertext unchanged, without a new seal.
- If the slot is absent, it seals only those exact admitted originals and calls
  the real no-replace `append`. The returned first bytes must exactly equal the
  candidate before return. A changed first publication or uncertain result
  fails; there is no reseal, retry or replacement fallback.

Actual store/owner configuration continuity, retained full-replay guards and
the original narrowed epoch/monotonic allowance bracket each storage/crypto
step and the final return. The same supplied work pays for replay, copying,
encryption and durable I/O. The signed-plan, state, delivery and historical
owner bounds are not renewed. A failure after visible publication may leave a
durable record; this module neither deletes it nor authorizes automatic retry.

Only ciphertext leaves export. Plaintext originals, old tokens, AES keys and
successful-verification carriers remain private. Existing ciphertext can be
returned only while genuine original live admission still succeeds; this is
not expired-history recovery or lost-locator discovery.

The .162 source connects root-admitted key/store configuration through the
actual [cold planner](oidc-session-activation-delivery-cold-planning.md),
[private service](oidc-session-activation-delivery-planner-service.md) and
[retained-export transport](oidc-session-activation-delivery-planner-transport.md).
The transport's ciphertext cap can be smaller than the store's whole-record
cap because it reserves the complete request, both headers and every other
response field. The service refuses an oversized raw7 response; uncertainty
does not mean durable storage was rolled back or authorize automatic retry.

Independent consume receiving custody/full replay and actual grant issuance
remain next, followed by reservation, one-use SQL and durable completion/recovery.
Exact committed-original release and public/portal handoff are not enabled.
No build, import, test, runtime check, key/directory provisioning or installation
was performed; step 20 and production acceptance remain open.
