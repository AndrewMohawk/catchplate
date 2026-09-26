# Owned native runtime lifecycle

Status: source-only, unbuilt and unexecuted. This composes the prepared native
gate with actual background work and serving under one owned lifetime. It does
not select a new CLI/environment startup mode, provision a listener, admit
configuration or complete production enclave deployment.

## From preparation to an owned run

The [bootstrap](enclave-bootstrap.md) still constructs `NativeTlsGateV1` without
starting workers. The main-private `serve_native_vsock_proxy(listener, prepared,
settings)` now delegates to [native_runtime::run](../data-plane/decision-gate-rs/src/native_runtime.rs).
It consumes the prepared object and requires sole ownership of its state before
installing `NativeRuntimeLifetimeV1`; it does not copy an already shared legacy
state or invoke environment-driven `main`.
The [callable native startup](native-startup.md) now constructs the actual
native owners and explicit shadow/v2 clients, performs preparation and binds
the fixed-parent listener before handing both owners to this run. It adds no
CLI/environment activation or independent admission.
The separate [native CLI configuration loader](native-startup-config.md) now
selects this sequence explicitly, before legacy environment startup.

`NativeRuntimeSettingsV1::new` accepts 1–24 proxy workers, queue capacity
1–4,096, policy interval 50 ms–60 s and audit interval 10 ms–60 s. These are
source resource bounds, not independent capacity or configuration admission.

```text
consume prepared owners and listener
    -> rejoin native identity, policy and actual custody health
    -> start scoped background work and require hot-generation readiness
    -> serve under the same lifetime
    -> stop, shut down sessions and join all scoped tasks
```

Before serving, the run rejoins the actual CA/ingress/proof scope and original
deadline, verifies current policy and performs synchronous native-proof and
response-observation-v2 health checks. The v2 check executes the actual pinned
hello: boot ID, provider readiness/generation, trust checkpoint and minimum
revocation epoch must match the retained client. It is not a caller-supplied
healthy flag or independent native admission of that service.

After workers start, hot credential-generation readiness has at most three
seconds, shortened to the remaining original lifetime. This is readiness for
the existing active scopes, not a speculative cold-scope request or new secret
warm-up operation. Failure prevents accepting proxy sessions.

## Existing operations, scoped workers

[native_background_workers::start](../data-plane/decision-gate-rs/src/native_background_workers.rs)
starts policy refresh, proof health and observation-v2 health tasks, plus audit
flushing when audit is configured. It uses the actual existing operation owners;
none of the detached legacy worker starters are called.

- Policy refresh calls `refresh_policy_snapshot(state, false)`. Transient
  failures retain the last good snapshot and the existing trust/dispatch gates;
  the worker waits the configured interval before retrying.
- Audit uses `pop_audit_batch` and `flush_audit_batch`, retaining acknowledgement,
  reservation, oversized-batch and retry accounting. A retryable failure already
  requeues through the existing owner and waits one second. Cancellation between
  pop and flush returns the exact batch through reservation-aware requeue.
- Proof health calls the actual signer's `probe_custody_once` on its existing
  one-second schedule. Failures update the existing fail-closed health state.
- The narrow `probe_response_observation_v2_once(client, max_duration)` wrapper
  reuses the existing pinned hello checks and health flag. Its periodic native
  caller waits one second and shortens the existing two-second probe bound to
  the shared remaining lifetime. Legacy health polling retains its old bound.

[Lease renewal](../data-plane/decision-gate-rs/src/native_lease_renewal.rs) is a
separate scoped owner in the same run, using the existing 50–1,000 ms interval,
1–32 workers and 1–65,536 queue capacity. It reuses actual active-scope candidate
classification and refresh without request/release authority; controlled
dispatch secrets remain excluded. Queue-owned pending guards preserve existing
accounting on receive, rejected send, cancellation, error and unwind. These
scope/generation rules remain distinct from health or listener readiness.
Transient failures do not prove successful refresh, audit delivery or healthy
custody. Policy/audit diagnostics use fixed messages; renewal identifies failed
scopes by digest, without printing returned errors or credential-bearing bodies.

## Stop and join, not detached shutdown

The [lifetime owner](../data-plane/decision-gate-rs/src/native_runtime_lifetime.rs)
retains the creator process and original `CLOCK_BOOTTIME` bound. Cancellable
waits observe both stop and the remaining bound. Scoped task startup failures,
unexpected completion, terminal errors or panics stop the group; stored failure
messages omit panic/error payloads. A stop-before-join guard also covers partial
startup, ordinary error returns and unwinding.

The listener and queued/active session shutdown custody share that lifetime.
Serving handlers and background tasks join before the run releases its retained
owners. Native service, provider, lease-acquisition and evidence paths check the
installed lifetime and reject new work after observed cancellation. These checks
do not atomically retract an already dispatched request, concurrent call or
other in-flight side effect.

Stopping does not promise a final audit drain or durable delivery of every
queued event. Requeueing preserves existing in-memory ownership while state is
retained; it is not a new durable journal. No fresh authority, secret fetch or
extended lifetime is created to make shutdown complete.

Synchronous filesystem, NSM, verifier, mutex and network work can still delay
joining. Cancellation closes owned inbound sessions and rejects further work
when observed; it does not forcibly interrupt every underlying operation. An external hard
watchdog remains necessary. This is not a hard real-time destruction receipt.

## Boundaries unchanged

The normal startup remains the legacy entrypoint. This callable lifecycle adds
no management listener, daemon installation or production admission. Native CLI
selection is now provided by the separate pinned-input loader, not this runner.
Independently admitted configuration, roots, service credentials,
release/PCR mapping, response-observation-v2 provenance, protected current
checkpoint/witness and rollback custody, KMS Recipient release, session
revocation, immutable packaging and frozen runtime verification remain separate
requirements. See [runtime identity](enclave-runtime-identity.md) and
[proof custody](enclave-proof-custody.md) for the unchanged authority limits.
