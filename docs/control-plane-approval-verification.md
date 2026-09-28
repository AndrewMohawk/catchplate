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
currently injects WebAuthn metadata directly with optional MFA. That setup must
be converted to a genuine signed assertion and verified receipt before the
consolidated source freeze, preserving its credential-revocation and trust-
withdrawal checks. The repaired transaction refuses its old shortcut; the fixture
has not been run or presented as passing evidence for this source.

After the complete source freeze, exercise all supported authentication modes,
both configured MFA policies, fresh valid assertions, wrong-action and
wrong-approval assertions, consumed challenges, raw-metadata forgery, duplicate
receipt consumption, expiry, credential revocation, role changes and concurrent
approval changes. Verify database/audit outcomes and browser continuation, not
only HTTP status codes. Full provider workflows and independently operated
production trust/custody services remain separate requirements.
