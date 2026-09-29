# Generic approval verification

This source repair connects genuine WebAuthn verification to the existing
generic control-plane approval transaction. It is unbuilt and unexecuted; it
does not close broader O04 provider operations or any production acceptance
gate. Workload issuance retains its separate cookie-only, mandatory-MFA path.

## One verification, one transaction handoff

The previous generic route tried to extract a raw assertion from the verifier's
result after the verifier had returned metadata and consumed the challenge.
The database also required both a raw-only assertion shape and incompatible
verified metadata. This caused refusals or exceptions, not a demonstrated
authentication bypass.

```mermaid
sequenceDiagram
    participant R as Approval route
    participant V as Verification receipt owner
    participant W as Genuine WebAuthn verifier
    participant D as Locked approval transaction
    R->>V: Original request, pending approval, assertion
    V->>V: Fresh authentication, CSRF, role and policy checks
    V->>W: Verify exact action and approval challenge
    W-->>V: Verified evidence; challenge already consumed
    V-->>R: Private one-use receipt
    R->>D: Receipt and intended approval
    D->>V: Consume against actual current row
    V-->>D: Bound verified evidence
    D->>D: Current role and credential checks, guarded update and audit
    R->>V: Discard on every exit
```

`serverware/control_plane_approval_verification.py` owns receipt construction,
registration, consumption and invalidation. It invokes the genuine verifier
itself. No public receipt constructor, posted success dictionary, serialized
receipt or caller-provided verification callback can select the verified path.
The receipt is an in-process source boundary, not hardware isolation against
arbitrary code executing inside the application.

The receipt binds the original request, authenticated actor, current policy and
approval identity, action, resource, payload digest, requester and expiry.
The database consumes it once against the real pending row while holding its
existing authority locks. It retains current role, distinct-approver and active
credential checks before recording the decision. A spent challenge is never
re-verified, and a failed or uncertain transaction does not make the receipt
reusable.

The original processing interval is at most 30 seconds and does not renew the
original challenge or approval expiry. Live checks continue through consumption
and the transaction's final read. This is an admission deadline, not a preemptive
watchdog for blocking filesystem, database or cryptographic calls.
The API always discards the private receipt;
raw assertions and request authentication material are not stored in approval
metadata or audit records. Existing allowlisted authentication summaries remain
the recorded evidence.

## Protected generated-admin-token publication

The active `POST /api/control-plane/tokens/admin/rotate` handler now delegates
to the fixed-purpose owner in
`serverware/control_plane_admin_token_publication.py`. It is not a generic
provider/effect callback and does not implement policy-file recovery (O05).
Externally supplied administrator tokens remain non-rotatable.

The owner freshly authenticates the retained HTTP request using the existing
header/bearer/OIDC/cookie precedence and CSRF checks. It samples one maximum
30-second processing interval before its fresh authentication, verification and
publication reads (not before the framework's prior body/dependency processing), checks
the actual administrator role, and retains the original request and policy.
Required MFA invokes the genuine action/resource/payload-bound WebAuthn verifier.
The shared mutation helper's authority-style raw-assertion shortcut cannot select
this effect: hints must agree with an actual verifier result. Raw assertions are
not journaled or audited. When the configured policy makes MFA or two-person
approval optional, that branch remains optional; workload issuance's separate
mandatory policy is unchanged.

The effect sequence is fixed:

1. Hold the protected service-owned token parent, a nonblocking journal lock,
   and the actual predecessor file descriptor/original. Secure path, service
   UID, mode, link count and identity checks use the
   existing policy-publication filesystem primitives, not native root-only
   assumptions.
2. Invoke the existing two-person gate against its real approval row in an
   owned metadata transaction. Stage a new random token, persist the exact
   old/new originals and immutable intent, then append the intent audit event in
   that same transaction as approval consumption. SQLite requires WAL and
   `synchronous=FULL`; PostgreSQL requires `fsync=on`, `full_page_writes=on` and
   transaction-local `synchronous_commit=on`. These are local durability
   conditions, as described by [SQLite](https://www.sqlite.org/pragma.html#pragma_synchronous)
   and [PostgreSQL](https://www.postgresql.org/docs/current/runtime-config-wal.html).
3. Only a definite successful transaction exit permits the authorized journal
   record. Clip the remaining original interval to the actual approval expiry.
   Recheck the current actor/authenticator and exact predecessor/staged files,
   durably record the irreversible claim, then attempt exactly one atomic rename.
4. Flush both affected directories and verify the actual installed inode and
   exact bytes against the retained staged descriptor. Persist the complete
   local outcome, commit the completion audit/outbox event, and then persist a
   separate settled record before returning the new token once.

The journal is `.serverware-admin-token-publications` beside the generated token:
service-owned mode `0700`, with no-follow, single-link, mode `0600` originals.
It is bounded to 64 attempts, seven fixed file kinds per attempt, 16 KiB per
record and 256 bytes per token original. Records are create-exclusive and form
one predecessor chain. No runtime pruning, repair, rollback, replay of token
plaintext, or retry after an uncertain commit/publication exists. Partial or
inconsistent files fail closed. A complete record without the final settled
record distinguishes an observed durable file outcome from an uncertain audit
acknowledgment and still blocks another rotation.

Generated-token authentication now reads the current protected file rather than
retaining an old per-process cached credential. Initial generation remains
create-exclusive; a missing token with an existing publication journal cannot
silently regenerate. The old ungated in-process rotation helper refuses use.
Successful HTTP responses preserve the token fields, add `publicationId`, and
are marked no-store. An absent response does not authorize resubmission.

### Inspecting an interrupted attempt

`GET /api/control-plane/tokens/admin/publication` requires an existing
administrator identity and returns bounded, read-only journal phases and whether
the current file matches an old/new original. It never returns either token,
changes the journal, resolves uncertainty, or grants a retry. Independently
configured OIDC administrator authentication remains available if the old token
has ceased working; an unavailable generated-token file fails that credential
closed without disabling the OIDC branch.

If no independently usable administrator identity exists, an authorized host
operator can inspect the protected journal directly under the existing service
UID/ownership boundary and correlate `admin-token-intent:<publicationId>` and
`admin-token-complete:<publicationId>` with metadata/audit records. The `.old`
and `.new` files contain secrets: do not print, upload, replay, delete, or rename
them as a recovery procedure. Read-only observation is not a repair procedure;
recovery authority, journal archival/pruning, multi-host coordination and an
independent rollback witness remain open. Local filesystem/DB flushes are not
off-host rollback protection or proof against a hostile service UID/kernel.
Blocking calls still require an external watchdog; the original interval does
not preempt them or renew after interruption.

## Preserve the actual authentication policy

The required-MFA receipt path reauthenticates the actual request using the
existing administrator authentication precedence: administrator header token,
administrator bearer token, OIDC bearer token, administrator cookie, then OIDC
browser session. Fresh request-local state avoids treating a cached browser
session identity as a current session check. CSRF and current action-role checks
remain part of that path; receipt creation accepts no caller-selected identity.

When the existing generic policy permits approval without WebAuthn, the ordinary
authenticated approval branch remains separate. It does not manufacture a
WebAuthn receipt or accept fabricated WebAuthn evidence. Enabling required MFA
does not fall back to that branch on verification failure.

Authority-style challenge or credential fields are at most consistency hints
alongside an assertion that passes genuine verification. They cannot authorize
the generic approval merely by being present. Other protected mutation flows
and the separate workload-issuance approval contract are not replaced by this
repair.

## Remaining acceptance

The `withdrawal_approval` setup inside `scripts/test_webauthn_attestation.py`
now retains the actual rotated credential key, obtains approval-bound options,
signs a genuine fresh assertion, authenticates the real request and invokes the
actual approval handler. Mandatory MFA is scoped to this fixture and restored
afterward; other registration callers and the post-withdrawal invalidation
assertion are preserved. It no longer injects verified metadata or enables a
development authenticator. This is a test-source correction only: the fixture
has not been executed or presented as passing evidence for this source.

After the complete source freeze, exercise all supported authentication modes,
both configured MFA policies, fresh valid assertions, wrong-action and
wrong-approval assertions, consumed challenges, raw-metadata forgery, duplicate
receipt consumption, expiry, credential revocation, role changes and concurrent
approval changes. Verify database/audit outcomes and browser continuation, not
only HTTP status codes. Full provider workflows and independently operated
production trust/custody services remain separate requirements.
