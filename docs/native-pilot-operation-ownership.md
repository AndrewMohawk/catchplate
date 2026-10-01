# Native pilot operation ownership and cleanup

This is a source-backed architecture decision for `.393`, not an implementation
or runtime acceptance claim. The selected native dispatcher and the existing
process-termination settlement contract currently describe different ownership
models. Neither a durable request fence nor successful service shutdown closes
that gap. No tests or live operations are reported by this note.

## What the selected path actually owns

[production.rs](../data-plane/decision-gate-rs/src/policy_custody/services/production.rs)
`run_production_rpc_service_scoped` creates four Rust thread workers and four
authenticated session threads. `production_worker` calls the retained bridge's
`handle_exact_request` under its mutex. `ConcreteFiveV3ProductionAuthoritiesV4`
owns authenticated ordinary-service sessions, native proof/signing endpoint
owners, and generation/dispatch/spool clients. It dispatches real authority
requests; it does not create a process for each operation.

The generic `BoundedServiceWorker` in
[services/mod.rs](../data-plane/decision-gate-rs/src/policy_custody/services/mod.rs)
also owns a `thread::JoinHandle`, including the helper's durability worker.
A thread-completion fence is not a process PIDFD or a process-reaping proof.

[native_guest/parent_process.rs](../data-plane/decision-gate-rs/src/policy_custody/services/native_guest/parent_process.rs)
does create genuine service children. Its `Child` retains the clone-return
PIDFD, checks the original parent and process start, and performs consuming
`waitid`. These are long-lived service owners, not per-operation workers.
Reaping a service would affect other operations and cannot be reported as
cleanup of one particular operation.

The older custody [launcher.rs](../data-plane/decision-gate-rs/src/policy_custody/launcher.rs)
contains `LaunchSpec`, `launch_retained` and `LaunchedProcess`, but the inspected
native source has no caller of `launch_retained`. Likewise,
[operation_driver.rs](../data-plane/decision-gate-rs/src/policy_custody/operation_driver.rs)
contains `PolicyCustodyOperationDriver::reconcile_startup`, which constructs
`WatchdogRecovery`; that driver is not constructed by the selected RPC path.
Extending these definitions alone would not connect operation cleanup.

## The existing v4 obligation remains real

[policy_shadow_custody_process.rs](../data-plane/decision-gate-rs/src/policy_shadow_custody_process.rs)
`request_worker_termination` sends `RequestTermination` for the exact operation
and termination fence; it does not itself establish termination.
`terminate_reap_fence_and_settle` calls `settle_operation`, which authorizes the
permit's cleanup and requests settlement under its original cleanup deadline.

`settle_operation` requires the tagged v4 terminal-cleanup artifact and checks
its exact operation, fence, worker executable, kernel driver, retained
descriptor set, driver-generation receipt, and signed-settlement original.
It passes the reported termination times, `process_reaped` and
`late_mutation_fence_closed` into `ProductionCustodyTerminationProof`.
The bridge's termination/settlement methods currently route to the generation
install proof endpoint. Routing a request is not evidence satisfying that
process-specific result contract.

The concrete first refusal is
[generation_install.rs](../data-plane/decision-gate-rs/src/policy_custody/services/native_guest/generation_install.rs)
`serve`: after marking its owner poisoned, it accepts only `GenerationAdmission`
and `GenerationConclude`. `RequestTermination` and `Settle` reach the wildcard
`BindingDrift` failure, not terminal evidence. Patching legacy static cleanup
intents alone cannot repair this selected receiver or its missing lifetime owner.

The [helper](../data-plane/decision-gate-rs/src/policy_custody/services/bounded_cleanup_helper.rs)
requires genuine parent/subreaper authority: `prove_worker_parent_relationship`
uses `waitid(P_PIDFD, WEXITED | WNOHANG | WNOWAIT)` and rejects `ECHILD`.
Later execution binds the retained PIDFD's same open-file description.
Passing a sibling's PIDFD does not transfer parenthood; enabling subreaping
does not adopt a live sibling's children. Keep those checks unchanged.

## Two honest architectural routes

1. **Satisfy the existing process model.** Introduce a fixed, genuinely
   operation-executing child whose real parent is the cleanup helper, with one
   consuming reap owner. Admission must bind the actual verified executable,
   operation identity, retained cgroup, capability set, and original operation
   and cleanup deadlines before execution. Export only duplicate capabilities
   for observation/registration; do not retain a competing parent-side reaper.
   This requires a new connected execution path, not a generic spawn interface
   or an idle placeholder process. Existing `launch_retained` requires a
   single-threaded launcher, verified rootfs/seccomp/root-switch authorities,
   an empty operation cgroup and watchdog registration. It cannot simply run
   inside the already threaded, privilege-dropped helper. Pre-drop preparation,
   actual parent topology and terminal failure ownership must be designed.

2. **Explicitly model native per-operation effects.** Define a successor
   contract that proves the operation's durable late-effect fence and final
   settlement across the actual retained service owners, without asserting
   process death. This fits the selected asynchronous dispatcher model, but
   requires an implementable no-late-mutation proof: every participating owner
   must enforce the same operation/fence, resolve in-flight or ambiguous work,
   preserve restart/replay behavior, and produce authenticated terminal
   evidence. The receiver must explicitly select the successor. Legacy v4
   stays closed; setting its process-reaped fields is not a migration path.

The original asynchronous proxy/durable-control design does not itself require
a new custody subprocess for every operation. Prefer the native effect model
only once its complete fence and settlement proof can be implemented; do not
choose helper-child topology merely to make an existing boolean pass.

## Next implementation order

1. Keep the selected bridge's durable pre-contact request fence separate from
   terminal cleanup. Such a fence can prevent ambiguous redispatch; it cannot
   prove that a contacted authority cannot mutate later or that a worker died.
2. Specify the actual operation lifecycle and terminal evidence for each
   participating retained service. Choose the process or explicit successor
   route against that evidence, including crash/restart and original deadlines.
3. Connect actual production dispatch, ownership admission, recovery targets
   and authorization consumption before permitting cleanup effects. Reuse the
   genuine verified-consumption boundary in
   [watchdog_recovery.rs](../data-plane/decision-gate-rs/src/policy_custody/watchdog_recovery.rs)
   where applicable; do not manufacture an owner or cleanup authorization.
4. Implement terminal production and independent receiver verification together.
   Unknown outcomes retain their real owners and fail closed. Only then verify
   the connected execution and failure paths; source completeness, helper
   registration, and thread/service shutdown remain insufficient evidence.

The next source pass must not mistake existing terminal append for complete
retirement. In `spool_head.rs`, terminal allocation checks pending allocations,
but does not require all retained effect barriers consumed; regular reservation
also lacks the terminal-ingress guard already used by effect allocation.
Consumption can include `OutcomeUnknown` or `ReconcileRequired`, so even a
consumed barrier does not prove resolved effects. Native signer `used`/`finished`
sets and cleared flights likewise do not provide durable restart-safe retirement.
Implement authenticated close-before-settle transitions and an exact outstanding
effect inventory, with explicit unresolved refusal, before producing a successor
terminal statement. These findings are source review, not live failure evidence.
