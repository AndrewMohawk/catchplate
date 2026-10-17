# Private activation receiving custody

The source now has an actual process-bound receiving owner,
[`OidcSessionActivationExecutionCustody`](../catchplate/authority_oidc_session_activation_execution_custody.py),
and a connected activation branch in the generic original-plan replay path.
This is not a deployed receiver, a provisioned key loader, a complete execution
service or production verification. No build, test or runtime result is claimed.

The owner authenticates the distinct [receiving bootstrap](oidc-session-activation-execution-custody-bootstrap.md)
and its embedded original planner-bootstrap v3. A planner sender statement or a
previously returned material object cannot substitute for receiving authority.

## Fixed private owners

| Consumer role | Required process mode | UID/GID |
| --- | --- | --- |
| `grant` | `oidc-session-activation-execution-authorizer` | 65506:65506 |
| `reserve` | `oidc-session-activation-execution-reserver` | 65505:65505 |
| `sql-issuer` | `oidc-session-activation-execution-sql` | 65504:65504 |

The exact owner class checks its PID, unchanged private configuration, real,
effective and saved UID/GID, empty supplementary groups and fixed
`CATCHPLATE_PROCESS_MODE`. Replay holds its nonblocking lock. Close removes the
held configuration; another process, changed configuration or concurrent replay
does not gain access. These checks do not create accounts or services, supply
private keys, attest executable bytes or widen existing registration roles.

The constructor is:

```text
OidcSessionActivationExecutionCustody(*,
    custody_bytes, root_public_key, consumer_role, expected_receiver_identity,
    bundle_key, delivery_custody_key, work,
    live_window=None, transport_deadline_ns=None)
```

`expected_receiver_identity` is an independently supplied, exact three-digest
identity: `sessionIdentityDigest`, `measurementDigest`,
`attestationReceiptDigest`. It is captured before callbacks and retained as
immutable canonical `_Configuration.receiver_identity_bytes`. It must match the
genuine outer statement at construction and after every replay reauthentication,
before key use or private opening. It must not be copied from that statement.
Cold delivery must independently bind this pin to its admitted runtime;
the comparison is not a measured-runtime proof. Trust remains host-local, with
all five hardware/native/HSM/TEE/witness flags false.

Both supplied AES keys are exact immutable 32-byte values. They must differ,
and each actual raw SHA-256 digest must match its root-admitted purpose pin.
The embedded planner profile independently separates those pins from its
journal key pin; the receiver does not receive the planner journal key.

## Real joins before original replay

```text
bind_context_on_work(*, root_public_key, current_root_enrollment_bytes, work)

replay_on_work(*, originals, expectations, planner_public_key,
    operation_public_key, before_vector_bytes,
    live_window, transport_deadline_ns, work)

close()
```

`bind_context_on_work` compares the generic caller's actual root SPKI and exact
current-root enrollment original with the held receiving configuration. This
static join returns no permission and does not establish current freshness.
The caller must still take the genuine live replay path.

`replay_on_work` requires the exact original pair `(signed_plan, encrypted_bundle)`
and closed ordinary expectations `{request, scope, journalDigest}`. Those data
are not successful-verification tokens. Before decryption, the owner:

- reauthenticates both bootstrap originals on the same work and original window;
- repeats the independent receiver-identity and actual private-key joins;
- binds the planner key to its admitted SPKI, and the generic operation key to
  the actual state-root SPKI;
- byte-compares the complete before-vector and state enrollment with the
  independently root-admitted originals;
- compares configuration, planner identity/SPKI, RP/origin, authentication/trust
  policy and plan age/skew against the genuinely admitted planner policy.

The owner then calls the actual [execution-original replay](oidc-session-activation-execution-replay.md).
That path authenticates the known signed plan before bundle decryption and
performs full original replay once. The owner returns only that same-call
ordinary `_ReplayedPlan`, after its final original-plan expiry check. Its private
configuration, material objects and decrypted records are not accepted in place
of original admission by a later boundary.

Keys remain private owner state. They are never added to bootstrap JSON,
generic SQL packets or replay results. The generic original inventory is raw2:
the original signed plan and encrypted bundle, not plaintext token originals or
decrypted journal bytes. Existing per-frame and cumulative original/work bounds
remain; no new allowance is allocated.

## Narrowing without renewal

[`authority_successor_execution_window._narrow`](../catchplate/authority_successor_execution_window.py)
has the signature:

```text
_narrow(live_window, *, deadline_epoch_ns,
    maximum_lifetime_ns, maximum_clock_skew_ns)
```

It preserves the original epoch/monotonic opening samples, takes the smaller
age and skew limits, and clips the epoch deadline and corresponding monotonic
deadline. It samples no replacement clock and creates no processing allowance.
A processing window stricter than the original signed policy is accepted; the
signed scope and its commitments remain unchanged. This permits an enclosing
grant's stricter limits without weakening the plan's actual policy.

Constructor key checks retain the inherited deadline through final configuration
checks. During replay, the owner retains sticky samples, both original launch
bounds, the inherited absolute cap and the narrowed window through its final
suffix. Full replay separately preserves assertion, session, delivery,
state-observation and signed-plan expiry. Expired originals cannot be made live
by a fresh invocation, another bootstrap verification or a later callback.

## Connected source, unfinished completion

The generic activation dispatch requires this exact owner plus a real live
window and inherited deadline. It invokes the actual class method; a posted
object with matching methods or a scalar success claim is not a substitute.
Non-activation families reject an activation custody argument. Historical
completion entrypoints explicitly reject activation; there is no backdated
clock or live-replay-as-history fallback.

Separate [historical original replay and caller/grant exchange](oidc-session-activation-historical-exchange.md)
now use genuine [historical plan](oidc-session-activation-historical-plan.md) and
[head/state admission](oidc-session-activation-historical-state.md). Their real
current processing allowance is distinct from expired original validity. These
partial completion/reconciliation primitives do not extend this owner's role
table, change its live APIs or confer current execution permission. Dedicated
historical cold custody and its independent purpose/key admission remain open;
none of the three live roles can be relabelled to provide them.

The [sender's durable first-exact export](oidc-session-activation-execution-export.md)
is a separate implemented source path. The **grant** receiver now has connected
source for its independent [role bootstrap](oidc-session-activation-execution-authorizer-bootstrap.md),
sealed [key/FD delivery](oidc-session-activation-execution-authorizer-delivery.md)
and actual service using [post-plan caller authorization](oidc-session-activation-execution-authorization.md)
and genuine grant production. This does not provision its UID, keys or listener,
and the packaged image and service remain unbuilt/unexecuted.

The **reserve** receiver also has connected [independent launch and checkpoint
admission](oidc-session-activation-execution-reserver-bootstrap.md), fixed
[eight-FD delivery](oidc-session-activation-execution-reserver-delivery.md),
genuine caller/grant/private replay and durable first-exact request/ACK storage.
Its state-v5 peer can reserve only this signed operation. An authenticated ACK
does not become its own independently current pending head.

The **SQL** receiver now connects [seven-FD delivery](oidc-session-activation-execution-sql-delivery.md),
genuine independent pending admission and the actual issuer/IDs-only executor
through its [dedicated service](oidc-session-activation-execution-sql-service.md).
Its attempt journal is separate and irreversible; no signed ACK supplies its
own independent pending authority. The unsigned commit observation does not
close completion/reconciliation, public recovery or protected token release. The
public caller's separate purpose/key lifecycle and present permission remain
open too. These source connections do not establish session currentness or
production acceptance.
