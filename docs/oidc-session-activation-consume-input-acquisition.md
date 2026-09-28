# Same-permission consume-input acquisition

`permission.acquire_and_prepare_consume()` connects the one-shot issuer to the
existing consume prepare/export path. It takes no caller-selected target, root
originals, resource pins or endpoint. Only the actual acknowledged activation
continuation can call it, and it spends the existing consume latch before work.

The explicit parent v13 configuration supplies a fixed public endpoint and the
independently signed issuer-policy original. Startup verifies static consistency;
the client performs genuine fresh policy admission under the permission's actual
original work/window before issuer contact. The request builder extracts raw16
only from sealed activation originals, original expectations/vector and the
actual pending-session cookie. Transport adds its fixed purpose as raw17.

The existing durable consume claim is published before the issuer request. A
bounded raw2 reply is retained as the optional `inputs` prologue before checking
whether either original is nonempty, correctly signed or for the expected
target. The full receiving verifier independently re-derives and authenticates
the returned history/planner payloads. The existing direct prepare path then
re-admits the exact originals against its own parent and target, reusing only
the same live permission's sealed claim. It does not restore a claim from disk.

The original ledger, clock floors, cookie, owner and permission remain pinned
through receiving and subsequent consume/release phases. Fresh policy and
returned original lifetimes can only tighten the caller's original allowance.
Whole-call inventory includes retained acquisition/derivation graphs and wire
bytes before contact; downstream planner response capacity is correspondingly
reduced. No new window, private key or result-as-permission object is introduced.

The original `prepare_consume(planner_bootstrap_bytes=..., history_custody_bytes=...)`
path remains available and claims before its planner I/O. Acquisition and direct
preparation share the same one-use latch; neither can repeat the other. Lost
responses or failures revoke the live permission and leave durable history for
read-only recovery, not automatic retry. Old-token request bytes are never
journaled or logged. A returned prepared/exported pair is not consume commit,
token release or a current authenticated session.

## Distinct fresh recovery caller

The separate recovery owner uses `_configuration_on_target(owner, target)` to
select cold configuration only. Exact current material identities select the
ordinary lane. An archived target instead requires the separate parent-v21
`historical_consume_input_acquisition` and its exact admitted archived scope,
root, interval and execution/planning objects. Missing or mismatched configuration
refuses; it never falls back, grants permission or replaces a target guard.

That helper returns the configured policy plus its **old** activation planner
original. The recovery owner retains its current signing root independently,
genuinely re-admits policy v2 and raw2 on the same work/window, and uses the
[bridge-aware prepare/export caller](control-plane-oidc-session-activation-completion-recovery-consume-planning.md).
The existing `_acquire_on_permission` and `_originals_on_permission` remain
unchanged and do not accept a historical result or revived permission.

The bridged caller and protected worker support private prepare/export only.
The public historical-consume gate remains closed until separate signed bridge
custody is implemented for grant, reservation, SQL and completion, including
historical completion of the new planner-v3 result. Planning history v7 supplies
none of those other roles; missing records cannot select a fallback or retry.

This is unbuilt/unexecuted source. Issuer startup and opt-in socket packaging do
not provision the independently pinned keys/resources. Explicit issuer launch v2
now stages the exact pair into the matching
[dynamic consume worker](oidc-session-activation-consume-dynamic-delivery.md)
before returning it; v1 does not. The public acquisition API cannot select that
launch version or treat its response as worker readiness. Actual provisioning
and production acceptance remain open; existing ordinary public, recovery and
portal paths are not evidence that the historical bridge is executable end to
end.
