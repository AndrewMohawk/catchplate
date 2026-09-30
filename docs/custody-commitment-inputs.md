# Ordinary commitment resources and five-service release

This is source implementation only. It connects the genuine five-service
software launcher to the two actual CommitRequest service handlers; it does
not create native evidence, keys, signed permissions or successful records.
The [native endpoint family](native-shadow-commit-request.md) remains separately
admitted. No build, test, parser, signing, provisioning or runtime was executed.

## Fixed selection and real resources

`FiveServiceLaunch.start_commitment()` alone opens root-owned0400
`/etc/serverware/custody-commitment-five.json`. The closed eight-field cold
configuration preserves the original boot, time namespace, invocation,
startup/lifetime and exact five executable/C9 pins. Version3 selects direct
entries; version4 selects the genuine retained privileged inspection entry.
The existing `start()` still accepts only generation launch/v1-v2 at its old
fixed filename. Direct mode does not weaken non-dumpable peer requirements;
the connected isolated native bridge needs inspected mode.

`BusinessResources.prepare_commitment(launcher)` admits only the exact actual
launcher and root-owned0400
`/etc/serverware/custody-commitment-business.json`, schema
`serverware.custodyFiveServiceBusinessInputs/v2`. It retains the same original
launch SHA/invocation and independently selected client C9 configuration.
The actual source-fixed `/run/serverware-custody-business` and
`/var/lib/serverware/custody-business` roots remain exclusive, root-owned0711.
Fresh listeners/business directories retain the .329 lifetime and no-adoption
rules. Nothing manufactures final peer UID/cgroup/label/IMA observations.

`resources.commitment_inputs()` supplies actual resource descriptors to the
closed input owner. No caller-selected resource registry is accepted in this
successor. Under each actual retained
`/var/lib/serverware/custody-generation/<role>` root, generation-journal and
generation-grant are prepared as before. Only the two commitment roles also
create a fresh persistent final-role0700 `dispatch-journal` and a zero-link,
final-role0600 `dispatch-grant` memfd. Both real identities exist before C9 is
approved/signed. Grant contents are filled later and sealed with all four
memfd seals. There are no synthetic journal records, generated grants, orphan
repair, replacement or automatic restart.

| Role | Signed FD6 onward inventory | Actual fixed entry |
|---|---|---|
| durable-recovery-store | listener, journal, generation-journal, generation-grant, dispatch-journal, dispatch-grant | commitment, runtime/v6 |
| cleanup-authorization-consumer | listener, state, journal, generation-journal, generation-grant | generation, runtime/v5 |
| recovery-target-provider | listener, journal, generation-journal, generation-grant | generation, runtime/v5 |
| current-signature-authority | listener, generation-journal, generation-grant, dispatch-journal, dispatch-grant | commitment, runtime/v6 |
| bounded-cleanup-helper | listener, journal, generation-journal, generation-grant | generation, runtime/v5 |

All five use their corresponding inspected entry under cold version4. FD3 is
the genuine retained parent channel; FD4 is the pinned fixed launch original.
The original source-verified executable is used for same-PID exec. The two
commitment roles get ordinary launch/v3 or inspected launch/v4; the other
three still get exact ordinary launch/v1 or inspected launch/v2.

## Independent originals before one release

For all five roles, `inputs.sign_delivery(...)` and
`inputs.seal_grant(...)` use the existing independently provisioned C9 and
authority-history signing owners on independently approved exact payloads.
They do not choose a permission, create a signing key or obtain a key remotely.
The two commitment roles use the explicit C35 successor authoring predicates.
The three remaining roles still pass the unchanged generation-only predicates.

For each commitment role, separately call
`inputs.seal_dispatch_grant(role, approved_grant_original=...,
native_grant_original=...)` with exact canonical signed public originals.
This method has **no signing-key argument**. It verifies the actual
history-root signature, role/C9/runtime/history/current-root selection and
scope; requires real LedgerAppend public material distinct from service/root
keys; binds the exact native grant original and expected bridge peer; and
requires the original BOOTTIME window to fit the actual generation/C9 lifetime.
It fills/seals/readbacks the allocated memfd once, then publishes the fixed
launch file exclusively. Unknown publication/sealing is not retryable.
Native supervisor/quote/currentness verification remains the native receiver's
job, and complete service authority-history/currentness remains the service
owner's job. A native envelope shape or local wall clock is not proof.

The five generation scopes must agree. Both dispatch scopes, native grant
originals and LedgerAppend keys must agree and match the generation successor,
driver/descriptor/generation receipt and assignment bindings. The public
`custody_commitment_inputs.bridge_selection(inputs)` returns only those exact
retained signed grant strings for independent bridge-runtime approval; it is
not a bridge constructor or readiness receipt.

`transfer = inputs.transfer(); launcher.release(transfer)` sends exactly one
source-fixed version2 release packet per actual parked child. The entire
attempt is irreversible before the first send. Original PIDFD/start/parent
ownership, watchdog, permanent drop and kill/reap remain unchanged.

For inspected mode,
`launcher.release_proof_cohort(cohort, release_original=..., transfers=...)`
requires the genuine six-owner cohort's `commitment_selected()`, not a supplied
boolean. It compares all five expected bridge PID/start/executable values with
the same parked owner, and requires all five authenticated final-role listening
notices before releasing any native child. It compares the actual retained
CommitRequest transfer's grant with the service-approved native original, and
the actual signed bridge C9 runtime pin's v6 selection with both sealed service
grant originals. The native cohort still verifies its own independently signed
whole release and every original/descriptor; this ordering grants no readiness.
The sixth-child/release/cleanup implementation is the separate native cohort/v3
producer, not an expansion inferred from this Python resource owner.

All resources/originals survive uncertainty and remain held until their actual
five children are terminated and reaped. The owner closes descriptors only
after that evidence; it never removes directories, journals or partial public
files. Native cohort cleanup remains separately owned. The other nine native
signer families, full driver bootstrap/settlement and connected pilot acceptance
are not completed by these source joins.

Closed configuration references:
[custody-commitment-inputs.v1](../schemas/custody-commitment-inputs.v1.schema.json).
