# Operator policy publication and audit acknowledgements

This is an operator-development repair, not native commissioning or production
authority. The retained Vdo private run exposed signed audit acknowledgement
failures during policy changes. Its failure counters remain failed evidence.

## Coordination contract

Both processes use the same empty, private, owner-bound
`/data/.operator-publication.lock` inode. Neither process replaces it during
publication. Each acquisition opens a separate file description; process-lifetime
descriptors retain the pinned inode identity.

- Python acquires its local reentrant lock, then filesystem EX ownership, before
  opening a publisher transaction. It holds ownership through commit, policy
  replacement and directory fsync. Nested materialization inherits that guard.
- Rust acquires its local serialization guard, then filesystem SH ownership.
  Before audit transmission it authenticates the settled policy again, captures
  the current snapshot, and keeps ownership through the complete response body,
  signature, currentness and acknowledgement checks. Startup holds SH before
  its first policy load through operator admission and high-water initialization.
- Audit ingestion, nonce reservation and policy reads do not acquire Python's
  publication guard. Post-publication HTTP observation occurs after releasing EX.
- Local/filesystem acquisition uses one five-second deadline. Rust retains that
  original deadline through trust refresh and dispatch drain; audit HTTP remains
  capped at two seconds and the remaining original budget. It never renews a
  credential lease merely because coordination took time.
- Missing, replaced, malformed or expired ownership refuses progress. A lock
  does not prove materialization succeeded: authenticated policy/authority
  agreement is still required. A committed but unmaterialized change remains
  pending, not an invented rollback or accepted active policy.

External attestation-verifier commands are explicitly unsupported by this
operator-development profile. The ordinary demo uses in-process development
signature verification. Custom commands now fail startup rather than entering
an existing subprocess path whose stdin write is not deadline-bounded. Ordinary
and native subprocess behavior is unchanged; this is not a fix for those paths.

## Existing-store upgrade prerequisite

Fresh initialization may create the lock only after the private operator marker
is admitted and a read-only probe finds no operator/catalog tables or policy
path. Existing or partial stores with a missing lock refuse automatic creation.
Generic startup can still perform its existing core database initialization
before the operator check; do not claim that refusal implies zero startup writes.

For an existing store, stop **all** old and new operator app and gate processes
before explicitly running the offline helper in the matching operator context:

```sh
python -m serverware.operator_publication --provision-existing-stopped
```

The flag acknowledges that prerequisite; it cannot prove services are stopped.
The helper verifies retained signed database authority and catalog bindings,
then provisions only the lock. It does not reset policy, replay state, client
tokens or credentials, or repair a pending policy file. Never use the helper as
an online migration or a way to replace a pinned inode. No existing live store
was migrated for this implementation.

## Evidence boundary

Primitive lock tests, Python transaction tests and local signed-HTTP ordering
tests cover different boundaries. The Rust ordering fixture models committed
authority in its synthetic receiver; it is not a SQLite or fixed-deployment-path
startup test. Neither set substitutes for a fresh actual private-proxy run with
strict zero-failure audit counters. See the
[verification record](operator-workspace-verification.md) for executed results.
