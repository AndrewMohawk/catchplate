# Consume-input issuer policy

This source-only contract admits a fresh, fixed-purpose root policy and a
separately supplied activation planner bootstrap original. It provides the
independent static inputs for one request's consume-input derivation. It is not
a cold service, root-key loader, resource provisioner or execution permission.
No successful material object is accepted as authority input.

## Exact independent policy

The signed and payload schemas are
`catchplate.signedOidcSessionActivationConsumeInputIssuerPolicy/v1` and
`catchplate.oidcSessionActivationConsumeInputIssuerPolicy/v1`. The purpose is
`issue-oidc-session-activation-consume-inputs`, with the actual source revision
and `trusted-host-local` trust mode. The closed payload has ten fields:

- `schema`, `sourceRevision`, `purpose`, `trustMode`;
- `activationPlannerBootstrapDigest`;
- `history`, `consumePlanner`, `activationPredecessor`;
- `issuedAtEpochNs`, `expiresAtEpochNs`.

`activationPlannerBootstrapDigest` is the framed identity of the full, separate
original, under
`catchplate.oidcSessionActivationConsumeInputIssuerActivationPlannerBootstrapIdentity/v1`.
The policy never embeds that original. Its own identity uses
`catchplate.oidcSessionActivationConsumeInputIssuerPolicyIdentity/v1`.
Policy bytes are capped at 64 KiB, 512 nodes and depth six; the activation
bootstrap retains its actual 4 MiB cap. Original and retained decoded bytes are
bounded by the existing 64 MiB aggregate, with work charged before native work.

`history` is exactly `receiverIdentity`, `bundleKeyDigest`, `deliveryKeyDigest`.
The identity uses the existing three-digest shape. Both AES pins must match the
genuinely admitted activation planner; they are not new keys or caller-selected
history permissions.

`consumePlanner` contains exactly `planner`, `databaseEndpoint`, `readRole`,
`tlsFiles`, `stateEndpoint`, `journalKeyDigest`, `executionBundleKeyDigest` and
`launch`. These use the actual consume planner v2 resource grammars: a dedicated
public key/SPKI/identity, fixed TLS identities and state endpoint, fixed process,
paths and descriptor inventory, bounded timeouts and independent journal/export
directory pins. The planner key is separated from the actual runtime root,
activation planner, configured generic and dedicated purpose keys, and enrolled
state/computation/completion keys. Consume journal/export AES pins and directories
must not reuse the actual activation custody purposes or each other.

`activationPredecessor` is exactly `sequence`, `headDigest`, `fence`, validated by
the actual activation reservation predecessor grammar. It is independently
root-held before caller evidence; a returned reservation ACK cannot choose it.

## Original-only APIs and lifetime

`_verify_on_work` requires `policy_bytes`, `activation_planner_bootstrap_bytes`,
`root_public_key`, and the original `live_window`, `transport_deadline_ns`, `work`.
An optional private `_continuity` exchanges only restrictive epoch/monotonic
floors; it cannot supply root admission or replace clock/work checks.
`_produce_on_work` accepts `payload` and the same independent original/current
inputs plus the actual root private/public key pair. It genuinely admits the
activation original and checks static joins before signing, then checks its
actual signed readback. It creates or loads no key.

The activation planner is admitted by the fixed historical verifier. Its source,
root signature, configuration, generation, runtime identities, planner key and
state enrollment are genuine original facts. Its old launch interval is evidence
only: a fresh policy neither renews it nor substitutes an old clock. Policy
currentness remains under the supplied original work/window/bound and sticky
inner and outer clock observations. Narrowing preserves the original first three
samples and can only reduce deadline, lifetime and skew. The policy lifetime is
bounded by the existing receipt limit, and processing is additionally clipped to
the genuine planner policy and consume launch timeout.

The private immutable result has twelve fields: `policy_bytes`,
`activation_planner_bootstrap_bytes`, `policy_digest`, `payload`,
`activation_planner`, `history`, `consume_planner`, `activation_predecessor`,
`consume_planner_public_key`, `live_window`, `deadline_ns`, `live`. Nested graphs
are owned diagnostic/output data, not reusable verification proof. `live()`
retains the original work and clocks and returns the current epoch.

## What remains with the producer and provisioner

Configuration/digest, generation, runtime identities/closure, authentication and
trust policy, age/skew/query policy and the exact state-enrollment original come
only from the genuinely admitted activation planner. A caller complete/control
graph cannot supply these expected authorities. The later original-only producer
must authenticate the acknowledged activation and derive the typed consume
request, activation expectations/scope, completed vector and fresh history and
consume-planner originals. This policy alone does not admit caller evidence or
prove completion, current state, durable retention, one-use enforcement or replay
prevention.

The root authorizes resource pins as policy; a signature does not observe their
filesystem presence, ownership, emptiness or availability. Independent resource
provisioning, private key custody, cold delivery, an acquisition service/client
and deployment evidence remain separate. No token, AES key, private signing key,
arbitrary template or executable payload is serialized in this policy.

The producer's separate historical activation-caller admission also accepts the
private optional `_continuity` hook. It threads directly into the existing
caller clock guard, including subsequent `live()` checks, so its epoch and
monotonic maxima can restrict the same original producer lifetime. The default
`None` behavior and all original signature/scope and historical-evidence checks
are unchanged; this hook does not grant replay or execution authority.

The actual consume-history producer/verifier and live consume-planner
producer/verifier accept the same optional hook. Their original signature,
purpose and interval checks remain mandatory. The hook passes through the
existing processing and live-launch guards, including opening/final fresh
samples, and through genuine nested historical activation admission. No caller
may select another history purpose or revive an expired planner using it;
omitting the hook retains each existing default path.
