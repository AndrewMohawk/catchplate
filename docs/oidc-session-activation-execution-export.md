# Private first-exact activation export

[`authority_oidc_session_activation_execution_export._export_on_work`](../catchplate/authority_oidc_session_activation_execution_export.py)
composes the actual configured plan owner, original journal and
[execution-bundle store](oidc-session-activation-execution-store.md). It returns
only the first exact durable ciphertext. This is source-only implementation,
not a public endpoint, generic replay-family registration or SQL integration.

The cold caller must genuinely authenticate the original root bootstrap and
independently join both owners, their configuration, keys and directory pins.
The exporter does not accept a bootstrap-success object as authority. Its
inputs are the actual `OidcSessionActivationPlanOwner` and
`ActivationExecutionBundleStore`, original signed envelope, independently
expected request/scope/primary roots/thirteen heads/journal digest, bundle key,
and the existing work/window/inherited deadline.

The source checks the store's six-field configuration against the actual
owner's twenty-one-field configuration. Source/configuration and the exact
bundle key must match; the bundle key must differ from both delivery and
original-journal keys. The store and original journal must have different
device/inode identities. These checks join supplied configuration; they do not
independently establish its provenance.

The actual owner's nonblocking lock stays held through the whole export.
Caller graphs are detached before cryptographic or file callbacks. The existing
`_verify_retained_locked` uses the mandatory independent journal ciphertext
digest: it authenticates the known plan before lookup, reads the bound original
journal record, and genuinely replays the original plan once. No new assertion,
token, plan signature or clock window is created.

From that same-call original journal scope and independently expected digest,
the exporter derives the closed seven-field
[bundle context](oidc-session-activation-execution-bundle.md). It calls
`store.read` **before any new seal**:

- If ciphertext already exists, the exporter opens those exact first bytes and
  compares the plaintext byte-for-byte with the freshly authenticated and
  replayed journal original. Store integrity alone is insufficient.
- If the slot is absent, the exporter seals those exact original bytes and
  calls the actual no-replace store append. It joins the returned ciphertext to
  the candidate before returning it. A competing first publication or any
  uncertainty fails closed; there is no reseal or retry fallback.

The whole-record and receiving aggregate bounds are checked before sealing.
Copies and byte comparisons debit the same supplied work. Owner/store
configuration continuity, the original processing bound, actual full-replay
lifetimes and original signed-plan expiry bracket each export step and the
return. A late failure can leave durable ciphertext; it never removes that
record or creates retry authority.

Only ciphertext bytes leave this function. No plaintext journal document,
token, private key or successful-verification carrier is returned. Existing
first bytes can be reused only while genuine original live admission still
succeeds: this is not expired-history recovery or lost-locator discovery.
Independent action permission, off-host currentness, generic grant/reservation/
packet custody, one-use protected SQL execution and token delivery remain
separate integration work.

Deferred frozen verification, **not run**: wrong owner/key/directory joins;
changed journal locator or originals; first-ciphertext reuse without sealing;
exact new publication and conflicting publication; expired replay or late
publication; configuration drift and poisoned storage; and ciphertext-only
output. No builds, imports, tests or runtime verification were performed.
