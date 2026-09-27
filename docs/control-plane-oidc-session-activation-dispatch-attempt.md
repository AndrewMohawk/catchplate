# Pre-planner activation dispatch claim

This dedicated local journal marker burns one retained finalization target
before the first activation planner request. It is metadata, not permission,
proof of planning, execution, completion or a successful session.

The exact client and journal API is:

```python
claim_oidc_session_activation_dispatch(
    *, finalization_digest, request_binding_digest,
    authorization_enrollment_digest, source_revision,
) -> None
```

The actual configured caller must genuinely authenticate the retained
finalization originals and current pending user/session/credential, consume
fresh target-bound permission, and keep the original processing guard. It
charges `MAX_CLAIM_IO_BYTES` before the stable native journal callback and
checks currentness before and after it. Only successful publication permits
the caller to attempt the first planner socket exchange. The journal does not
repeat original replay or accept a successful permission object.

The slot is `activation-dispatch-claimed-<finalization digest hex>`, keyed by
the exact retained finalization locator. A changed assertion, request binding,
caller enrollment, plan or source revision does not create a new slot for that
target. After restart, even identical recovered metadata denies fresh dispatch.
This differs deliberately from the release-client marker, whose key is a
separately issued root client authorization.

The fixed `SWCAD001` codec stores only three canonical SHA-256 commitments and
the bounded source token. Its four fields are `finalization_digest`,
`request_binding_digest`, `authorization_enrollment_digest` and
`source_revision`. New encoding requires the current source cohort; decoding
preserves older source metadata without granting authority. The record ceiling
is 362 bytes and the fixed caller I/O charge is 1,086 bytes. Exact lengths and
EOF are required. No request, assertion, old/new token, private key or other
private original enters the marker.

The actual custody journal uses no-replace publication, file/directory
synchronization, normal close and exact readback before success. File identity,
private directory identity, PID and live-owner checks remain required.
Publication/readback uncertainty poisons the current journal; unknown or
temporary files fail recovery closed. No record is removed or rewritten to
permit retry. A recovered marker remains terminal even if no planner response
was received.

Claims share the existing logical record ceiling with prepared records and
release claims. The physical ceiling, quota and reserved legacy marker budget
are unchanged. This namespace is not a prepared record or a generic forwardable
operation. Existing pending, receipt and original-retention paths are unchanged.

Only the pre-planner claim is added here. There are no speculative plan, grant,
reservation or outcome slots, no new HTTP dispatch endpoint and no recovery
permission. Public activation step 22 remains partial until its actual pipeline
is connected. Filesystem durability depends on the provisioned filesystem;
source implementation is not runtime durability, anti-rollback against a
privileged host, provisioning or production acceptance evidence.
