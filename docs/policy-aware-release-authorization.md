# Policy-aware ordinary release authorization

This explicit ordinary profile repairs the producer/consumer commitment mismatch
without changing legacy signed bytes or calling ordinary custody native. It is
representation compatibility, not additional actor, credential or provider
permission. The source remains unbuilt and unexecuted; no production gate follows
from these contracts.

## Selection and preparation

The ordinary data plane must select PolicyAware from its actual cold configuration
before preparation or reservation, and retain it through response proof and lease
ownership. Independently pinned receiving expectations must select the same
profile; no request header, successful diagnostic or returned version may upgrade
legacy. Native remains a distinct source-selected profile. The ordinary switch
must not become reachable before the controlled-lease and independent-proof joins.

`POST /api/data-plane/release-authorizations/policy-prepare` accepts only
`catchplate.policyAwareReleaseAuthorizationPrepare/v1` or `/v2`. Its closed request
contains `apiVersion`, `attemptId`, `flowId`, `principalId`, `routeId`,
`credentialRef`, `credentialVersion`, `policyHash`, `requestDigest`,
`operationDigest`, `operationContext` and `canonicalRequest`; v2 additionally
requires the existing exact `durablePolicy`. Preparation does not take
`approverPolicySha256`. Principal and other identity scalars retain the ordinary
256-byte UTF-8, trim-stable, control-free profile, not native-wide principals.

Preparation repeats the real authenticated actor, active policy/route,
credential-generation, canonical request/operation and durable-scope checks. It
only reads authority: no reservation, quota/grant consumption, maintenance or
provider effect. The existing deployment-aware normalization supplies configured
WebAuthn RP/origin and current route approvers rather than reconstructing them
from route fields alone.

The unchanged nonce-bound `responseSignature/v3` authenticates the exact body.
The [preparation schema](../schemas/policy-aware-release-authorization-preparation.v1.schema.json)
has eight fields: `apiVersion` is
`catchplate.policyAwareReleaseAuthorizationPreparation/v1`, followed by
`principalId`, `routeId`, `policyHash`, `requestDigest`, `operationDigest`,
`approverPolicy` and `approverPolicySha256`. The policy is the existing normalized
eight-field object with twelve-field `credentialPolicy`, or explicit null for
the actual non-JIT route. Its compact sorted `ensure_ascii=True` JSON, including
null and escaped DEL, is hashed with SHA-256. The versioned policy retains the
64 KiB bound and positive-u64-or-null trust-bundle sequence. The receiver uses its
original nonrenewing deadline and bounded 96 KiB preparation-response lane.

## Reservation and retained transitions

The existing `/reserve`, `/dispatch` and `/complete` endpoints accept separate
`catchplate.policyAwareReleaseAuthorizationReserve/v1|v2`,
`catchplate.policyAwareReleaseAuthorizationDispatch/v1|v2` and
`catchplate.policyAwareReleaseAuthorizationComplete/v1|v2` requests. Reserve has
the preparation fields plus mandatory `approverPolicySha256`. The control plane
recomputes the actual current normalized policy and refuses drift before reserve
effects. Other closed fields and v1/v2 durable omission rules are unchanged.

The full binding uses
`catchplate.policyAwareReleaseAuthorizationBinding/v1|v2` in `api_version` and
retains `attempt_id`, `flow_id`, `principal_id`, `route_id`, `credential_id`,
`credential_version`, `policy_hash`, `request_digest`, `operation_digest`,
`operation_context`, `require_jit_grant`, `approver_policy` and `shared_quotas`.
`approver_policy` is always present, including null; v2 additionally retains
`durable_policy`. Its canonical digest and exact version are persisted before
effects. Every replay, dispatch, completion and controlled-lease authority check
compares that retained representation, not merely a native boolean or durability.
Legacy/native/policy-aware substitution is refused.

Responses are `catchplate.policyAwareReleaseAuthorizationResponse/v1|v2`, with
the existing response fields and signature recipe. Returned authorized/live
results require the retained matching binding marker. Existing current-policy,
WebAuthn, RBAC, quota, durable-bundle, uncertainty and one-use guards remain active.
Legacy callers retain the old wire recipes and their known binding mismatch;
selecting the explicit new profile is not an automatic legacy migration.

## Credential and proof boundary

Paired `catchplate.policyAwareCredentialLeaseRequest/v1|v2`,
`policyAwareCredentialLeaseRequestAuthority/v1`,
`policyAwareCredentialLeaseReleaseAuthorization/v1|v2`,
`policyAwareCredentialLeaseEnvelope/v1|v2` and
`policyAwareCredentialLeaseSet/v1|v2` families preserve their existing closed
field/null inventories while committing this separate representation. Controlled
issuance rejoins the exact retained PolicyAware binding and current normalized
JIT authority before its irreversible claim. Versioned AAD and request hashes use
the canonical originals; metadata hashing and the existing HKDF recipe remain
unchanged.

PolicyAware recipient admission requires genuine evidence even in development,
independently pinned PolicyAware expectations, an exact `leaseRequestApiVersion`
echo, matching authority fields and `debug: false`. Sharing the original role-2
verification primitives does not label an ordinary recipient native. No lease
schema, preparation result or proof diagnostic alone authorizes provider I/O,
workload launch, canary success or production promotion.
