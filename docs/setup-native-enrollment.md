# Native Setup certificate issuance

This is an additive protected successor to actual OAuth Setup revision 3 and
the immutable candidate association at continuation revision 0. It does not
change legacy enrollment receipts or advance the legacy Setup row. The effect
is **certificate issuance only**, not CA installation, enrollment completion,
native runtime verification, proxy readiness or final challenge consumption.

## Actual source path

`control_plane_workload_identity_routes` opens the existing cold native issuer
request owner before body collection. The selected Setup HTTP module retains
that same owner, deadline and originals. Its requester is the actual OIDC owner
with both literal `credential_owner` and `policy_author`; the deciding OIDC
`approver` must be another person. No administrator role alias is substituted.

The protected `setup.native-enrollment.request` and `.decide` operations use the
existing genuine `policy_authority` WebAuthn verifier and current trusted-key
rows. They do not write the legacy workload approval path. `.prepare` atomically
consumes that exact approval, consumes a fresh requester assertion and inserts
the immutable `setup_native_enrollments` contact fence with phase
`issuance_unknown`. Only after the controlled commit and exact readback does
the HTTP owner invoke `_issue_on_context` once on the already admitted fixed
issuer socket. The issuer retains its existing durable grant claim, independently
assigned CA key and exact leaf builder. No key or grant is generated here.

Both independently configured authority verifier and planner reverify the native
bootstrap, grant, delegation/setup originals, CSR possession and returned leaf
under separately pinned issuer authority. The explicit signed configuration
field `setupNativeEnrollmentPolicy` binds that public issuer root, exact original
bootstrap SHA and the full existing hardware policy. The issuer root must differ
from the controlled-writer root. Existing issuer admission additionally enforces
its own role separation. No response shape, uploaded success object or native
capture diagnostic stands in for any signature. This native-request-first issuer
profile retains its actual **trusted-host-local** CA-custody label.

The `.complete` controlled CAS requires the same intent, consumed approval,
Setup/continuation originals, current active publication, credential currentness,
original deadline and independently verified certificate. It retains the exact
public certificate and source-verified issuer association, then records
`certificate_issued` at sidecar revision 1. All four operations use the real
protected audit outbox. They confer no audit-inclusion or final Setup authority.

## HTTP and uncertainty

The closed bodies and output profiles are in
[`setup-native-enrollment.v1.schema.json`](../schemas/setup-native-enrollment.v1.schema.json).
Fixed POST endpoints are `/api/setup/native-enrollment/draft`, `/options`,
`/request`, `/decide`, `/issue`, and `/lookup`. Draft consumes the original native
grant, packet and target request using the existing byte-count/digest/base64url
wrappers. It retains the actual cold bootstrap inside an exact ASCII intent.
An intent is bounded to 1,200,000 bytes and its unchanged interval to at most
300 seconds; the signed grant, certificate and Setup expiry can shorten it.
Every actual HTTP operation retains the original bounded issuer request window.

Options select request, decide or issue and return a purpose-bound hardware
challenge. Request returns 428 with the actual pending approval ID; a different
approver imports the **same intent** and decides. Issue returns 201 only after
verified issuer output and the protected completion CAS. The browser must mark
each effect unresolved before contact. No automatic retry or intent replacement
is allowed on uncertainty. An absent response is not evidence of nonissuance.

Lookup is a separate read-only owner; it does not contact the issuer or require
an expired issuer grant to become current again. The Setup owner can retrieve
the exact stored certificate and association when the protected record is
definitely `certificate_issued`, including after a lost 201 response. Such output
is a historical observation, not renewed certificate validity or permission to
act. An unknown row remains fenced. An absent row does not authorize another
attempt. Neither lookup nor expiry removes a row or clears browser uncertainty.

## Portal handoff

The Setup native-enrollment controls use the session ID already entered in
Setup. The requester selects the exact grant, packet and signed CSR request;
the private key stays on the workload host. Review displays the exact
principal, policy, assignment, issuer, request and intent digests. The unchanged
intent and approval ID move only through an authorized operator handoff.
These originals can carry authority: never publish them in chat, tickets or logs.

The browser uses the six protected routes above, not the legacy workload
approval mutation. Each effect requires a fresh purpose-bound passkey and
current OIDC role/session checks. Before possible submission it stores only
nonsecret attempt IDs/digests in session storage. File, intent, session or auth
changes discard the in-memory review and certificate; they never clear attempt
markers. Readback can recover the exact historical certificate without a new
issuer contact. A download is not proof of local admission or installation.

The connected candidate-binding predecessor reads the actual protected
`credential_version` column, rather than the public credential DTO's
`version` alias.

## Remaining gates

The independently signed authority policy, actual native issuer bootstrap/grant,
current protected policy, active credential, native packet and target private-key
owner must already exist. Provisioning and runtime acceptance are not performed
by this source change. The separate [authenticated host CA readback flow](setup-native-ca-installation.md)
now connects a purpose-signed observation from the actual installer.
`nativeCaInstallationReceipt/v1` remains a local diagnostic, and the local
`--admit-native-workload-certificate` path is not a remote installation receipt.
Trusted-host-local readback does not establish measured host assurance.
Actual native canary/runtime/hardware progression
and the independent final Setup receipt authority remain separate unfinished
integrations. No build, parser, test, browser, signing or runtime action was run.
