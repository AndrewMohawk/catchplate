# Finalization caller enrollment and pre-plan issuance

This source-only path produces the dedicated finalization authorization
**before** its future plan. It does not upgrade evidence-admission authority,
retime an existing raw7, authorize SQL by itself or activate a session. No
tests, imports, builds or runtime verification ran in this batch.

## Independent delegation

[`authority_registration_finalization_authorization`](../serverware/authority_registration_finalization_authorization.py)
provides these private source entrypoints:

- `_produce_enrollment_on_work(...)` signs the finalization caller enrollment
  with the independently held root key, then genuinely admits its original.
- `_admit_enrollment_on_work(...)` authenticates that original root signature,
  configuration/database/generation, current-root/grant enrollment identities,
  authorizer audience and actual caller key/measurement. It returns private
  same-call policy/key facts; no input accepts those instead of originals.
- `_sign_request_on_work(...)` is a fixed private signing suffix for the actual
  original-replay issuer, not an arbitrary-domain signing endpoint.
- `_verify_on_work(...)` verifies the original request signature, purpose,
  enrollment, derived request/operation identity and live original interval.

The enrollment producer takes original current-root and grant enrollments,
root private/public keys, independent configuration digest, caller public key,
measurement and ID, planner/evidence public keys, maximum age/skew and the
existing work allowance. The root's policy/identity approval and key custody
are external prerequisites; constructing these arguments is not root admission.
The verifier accepts the corresponding original enrollment plus independently
admitted root/configuration/planner/evidence pins.

Both enrollment and request are closed canonical originals for
`authorize-registration-finalization` and `webauthn.registration.finalize`,
using the distinct finalization schemas and domains documented in
[execution admission](registration-finalization-execution-admission.md).
Evidence-execution or evidence-signing originals do not substitute. Actual
caller separation from authority and plan/evidence keys remains mandatory;
the cold owner must additionally enforce its independently admitted purpose-key
and descriptor inventory. No key is provisioned here.

## Actual signer-original issuance

[`authority_registration_finalization_issuance._produce_on_configuration`](../serverware/authority_registration_finalization_issuance.py)
has this keyword-only contract:

```text
payload, configuration_digest, generation, runtime_role_identities,
request_originals, response_originals, sibling_challenge_ids,
authorization_enrollment_bytes, current_root_enrollment_bytes,
grant_enrollment_bytes, root_public_key, caller_private_key,
live_window, work, transport_deadline_ns=None
    -> original signed authorization bytes
```

The caller must authenticate the present actor and exact finalization purpose
before invoking it. Request raw8 and response raw2 undergo the actual source,
enrollment, ceremony, attestation, trust and evidence-signature replay in
[`authority_webauthn_registration_signer_response`](../serverware/authority_webauthn_registration_signer_response.py).
Its separate fixed finalization-issuance branch derives the complete typed
finalization request; it does not accept a caller-supplied digest or credential.
The existing finalization `(request, inputs)` API is unchanged.

Sibling IDs are sorted, unique, bounded hints (at most 32), not proof of the
population. The later real planner must prove complete live siblings and
credential history plus the committed, unconsumed v2 evidence row. Changing
the request or hints between authorization and planning cannot be hidden by a
new request digest: the grant producer must join the exact original commitment.

All ten originals and three enrollments share the existing 64 MiB aggregate
bound and source per-original/group caps. Configuration, generation, runtime
cohort and sibling graphs are detached before native callbacks. Real finalization
configuration supplies planner/evidence pins and excluded runtime key identities.
The new caller enrollment and actual private/public pair are verified before
request signing. A fresh nonzero raw32 random identifier distinguishes the
original authorization; it is not a one-use journal or replay barrier.

## Current issue, unchanged expiry

After original replay, root delegation and key checks, the issuer samples the
actual current clock for `issuedAtEpochNs`. It never copies the earlier source,
evidence or enrollment-grant issue time into a new authorization. Expiry is at
most the intersection of those original expiries, original request deadline,
the supplied processing window and enrolled maximum age. No new outer window
or work allowance is opened. Inherited monotonic bounds only narrow the original
window; sticky wall/monotonic checks bracket replay, signing and final genuine
verification of the new signed original.

The required sequence is: present-caller purpose admission → genuine request
reconstruction → current-time authorization → a new matching live plan →
separately admitted grant/reservation/protected execution. An older retained
raw7 cannot receive this later fresh authorization, because the grant must
preserve its plan issue time and that time cannot precede authorization.
Replanning is an explicit separately admitted continuation, never an automatic
retry. Expired source originals require a new authorized flow, not renewal.

This pure issuer does not open a socket, create a cold owner, retain bytes,
reserve roots, claim an SQL attempt or sign completion. The separate
[public grant-preparation path](public-registration-finalization-grant.md) now
connects genuine ownership and present-purpose admission to this issuer,
same-read new-plan/vector acquisition, the
[dedicated cold authorizer](registration-finalization-authorizer.md) and durable
raw10/finalization association referencing the existing evidence/signer pair.
That integration remains source-only,
unbuilt, unexecuted and unprovisioned. Live current-root/pending admission and
protected SQL/completion orchestration remain downstream obligations. The
registration kernel does not mutate OIDC session activation, which remains separate.

Deferred frozen coverage must exercise distinct-purpose rejection, original
replay/request mismatch, key separation, actual issue-time ordering, no lifetime
renewal, clock reversal, expiry during callbacks and shared-work exhaustion.
Source implementation does not close a production acceptance gate.

## Bounded finalization grant transport

[`authority_registration_finalization_transport`](../serverware/authority_registration_finalization_transport.py)
defines the distinct `SWRFGQ01` request and `SWRFGR01` response. The request is
exact raw9: original authorization, original custody raw7, then the complete
before-vector. Each body has its existing original limit (custody limits are
intersected with actual plan-replay limits), and the full request is at most
64 MiB. The response is one original grant of at most 64 KiB. Fixed-width
big-endian byte lengths are validated before body allocation; trailing or
truncated frames fail.

The private `_originals(values, limits)` accepts only the exported fixed
`REQUEST_LIMITS` or `RESPONSE_LIMITS` profile. `_socket_request(endpoint, *,
originals, deadline_ns)` requires the caller's existing absolute monotonic
deadline and only narrows it by the configured integer 1–30 second timeout.
The endpoint must be `/run/serverware/registration-finalization-authorizer.sock`
with the independently configured root `0:0` listener peer; peer credentials
are checked before sending or reading a response prefix. The request is
half-closed, and response success requires exact EOF. There is no retry,
fallback, JSON decoding, signature verification or new work allowance here.

`_recv_request` and `_send_response` are framing helpers, not authority. The
[dedicated cold authorizer service](registration-finalization-authorizer.md)
now authenticates its actual client peer before body reads, genuinely verifies
the fixed-purpose originals and closes its response under the original bounded
request window. This is source implementation, not a deployed service. The
receiving caller must independently
verify the returned original grant against the same authorization, raw7,
before-vector and admitted configuration/enrollments. Neither a root listener
credential nor a complete frame establishes signing authority, currentness,
reservation, protected execution or completed registration. This transport is
source-only and unexecuted.
