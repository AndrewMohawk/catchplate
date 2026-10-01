# Current-state decision worker

The pilot's eight current-head approvals require more than authentic historical
signatures. This worker compares each real request and its complete public
evidence with an independently delegated **live current-state store** before
publishing the existing Input3 and Approval2 originals. The existing checkpoint
authority performs the later signing; the worker has no signing keys.

This is an initial-bootstrap decision path, not a general checkpoint authority,
an off-host witness, or proof of independent production administration.

## Current state, not history relabeled as fresh

The separately supplied worker policy pins the actual state and receiver
directory identities, supervisor inventory, original clock domain and limits,
and the exact admitted current-state digest and generation. State contains all
eight service/endpoint targets, their root/checkpoint authorities, invocation,
deployment/process identity, checkpoint and generation/revocation facts, and
active or revoked status. It is explicitly supplied by the state authority;
the worker does not initialize it from a request's historical evidence.

For each request the worker reads the actual named `current.json` under the
shared state lock. The pinned baseline must still be current, the target must
be active, and all authenticated evidence must match. A revocation or any state
revision invalidates this bootstrap run; the worker never silently adopts a new
state or renews a request. Each actual request's original validity must fit
inside both the delegated policy and state limits.

The lock covers a durable one-use consume receipt followed by input-first,
approval-last publication. A partial failure cannot be retried by deleting a
receipt or overwriting an output. A fresh process encountering prior outputs
does not resume them. Full request/nonce/input/approval/state bindings remain in
the public receipt for reconciliation.

The first actual job supplies the literal conductor request. Later jobs must
match its retained digest; no synthetic pending-request wrapper is invented.
Complete Input3 validation and the existing approval installer checks still run.

## State updates and publication

The fixed state directory is
`/etc/serverware/native-pilot-current-head-state`, root-owned `0700`.
The separate state-update command accepts a protected, independently pinned
authorization original. Initial state can be installed only into the explicitly
selected empty directory. Later updates require the exact prior state digest
and generation under an exclusive lock; generations increase monotonically,
scope cannot change, revoked targets cannot be reactivated, and validity cannot
be extended. No initializer derives state from a historical signature.

Every authorized state writer must use this same serialization path. Local
ownership, file locks and policy pins do not protect against a hostile root
administrator rolling the whole filesystem back. Independent state ownership
and the separate production rollback witness remain deployment requirements.

The receiver now publishes complete request/evidence files atomically. Worker
inputs and approvals likewise become visible only after complete writes,
readback and fsync, with no replacement of existing output names. An incomplete
file is never used as the readiness signal. The selected Linux filesystem must
support the actual anonymous-file and atomic-link operations; no weaker
publication fallback is selected.

## Fixed entrypoints

Both modes are in the admitted supervisor package and accept only protected
public FD/hash pairs, not arbitrary paths, commands, key bytes or network URLs:

```text
current-head-worker
  --supervisor-inventory-fd FD --supervisor-inventory-sha256 sha256:HEX
  --policy-fd FD --policy-sha256 sha256:HEX

current-head-state-update
  --supervisor-inventory-fd FD --supervisor-inventory-sha256 sha256:HEX
  --authorization-fd FD --authorization-sha256 sha256:HEX
```

These are capability contracts, not a copy-paste deployment recipe. The
`prepare_native_pilot_resource_roots.py --profile commissioning-decisions`
helper inspects operational/startup roots plus the empty state root. Explicit
`--create` adds missing directories only; it does not seed or approve state and
will not empty existing roots.

The worker is independently launched alongside the
[three-process commissioning startup](native-pilot-startup.md); it is not an
implicit fourth child with borrowed provider authority. Its policy/state must
be provisioned from real checkpoint issuance before the original 30-second
driver startup window expires. This still needs automated late provisioning.

## Pilot boundary

The source alone does not establish an installed authority or a successful
application flow. Approved matching packages, independent policy/state custody,
automated provisioning and the real credential-replacement allow/deny/cleanup
run remain required. No production acceptance follows from local fixtures.
