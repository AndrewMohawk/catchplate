# Native canary publication associated with Setup

This connects existing native producers to a new protected Setup consumer. It
does not introduce another receipt signer, relabel legacy receipts or perform a
native effect. The immutable result is `canary_publication_associated`, not
proxy readiness, hardware assurance, permission to send a request or final Setup.
Legacy Setup revision 3 and the old enrollment/hardware/final receipt chain are
unchanged.

## Actual producer-to-consumer path

The inputs already have real producers: native canary evidence intake and READY,
distinct hardware-backed native activation request/approval, the actual custody
publication CAS and signed receipt, its audit inclusion and native finalization.
The existing `committed_policy` predicate reconstructs that current publication
from actual native/legacy heads, READY/preparation, the independently assigned
publication key, exact signed receipt and four completed audit originals.

`setup.native-canary.record` consumes none of those permissions again. Its
protected transaction proves the exact current rows and joins them to the
immutable Setup candidate association, issued certificate and authenticated
host CA readback. It rechecks the active credential/currentness root and exact
current policy tuple. A complete bounded finalization range refuses ambiguity.
The original issuance and native activation two-person approvals remain exact;
the requester and approvers retain their required roles. Fresh requester
hardware is required for this new metadata effect. Both independently configured
authority roles select the existing cold CA and activation purposes; the native
activation policy hash cannot be replaced by an uploaded key or request policy.

All nine required completed audit rows are selected and rechecked: four retained
native activation audits, finalization, issuance prepare/complete and host CA
prepare/complete. The finalizer's original canonical four-row audit list has a
purpose-fixed decoder; the shared object-only JSON decoder is not relaxed.
This corrects the concrete list-to-object mismatch in the existing committed
publication caller. No audit status is inferred from a successful HTTP response.

The association inserts one immutable protected slot and its own audit outbox
event. It never updates the legacy Setup row, consumes an old receipt again or
clears an unknown predecessor. Prior issuance/installation effects must have
completed within their original intervals. The metadata ceremony has its own
at-most-30-second interval clipped to the original Setup expiry; it does not
renew grants, certificates, readiness, trust or workload lifetime. After the
association, the publication may change: this is a record of the checked instant,
not a continuing currentness lease.

## Fixed operator caller

The four POST routes are `/api/setup/native-canary/draft`, `/options`, `/record`
and `/lookup`. Draft and lookup accept only the profile and actual Setup session.
Draft selects exact server-held originals; callers cannot upload a canary success
object, certificate, quote or publication receipt. Options and record carry the
same canonical `argumentsOriginal`, with a fresh assertion only for record.
Originals remain in memory. Before record dispatch the caller must retain a
nonsecret unresolved-attempt marker; uncertainty never permits resubmission.

The requester is the genuine OIDC owner with literal `credential_owner` and
`policy_author`, unchanged Origin/CSRF and current hardware policy. All reads,
assertion admission, controlled contact and readback share the original request
owner/window. Record returns 201 only after exact protected row readback.
Lookup returns the retained historical row after a lost 201 without reissuing,
refreshing or contacting the native runtime. An absent row is not retry authority.
The [closed schema](../schemas/setup-native-canary.v1.schema.json) fixes HTTP
32 KiB, canonical arguments 16 KiB, retained association 32 KiB and response
64 KiB bounds. No browser/native signing or new private key is involved.

## Portal review

The Setup portal includes this exact draft/options/record/lookup flow. Review
shows the server-selected credential, policy, completed publication and
predecessor hashes; there is no input for uploading a readiness verdict. The
unchanged canonical arguments and their exact digest bind the fresh passkey
options. Both the original expiry and a monotonic local review limit are
checked before submission. Only a nonsecret digest is stored as the unresolved
attempt marker. Auth/session changes discard review data, not that marker.
Lookup displays historical association only and cannot unlock another record.

## What remains for a usable pilot

This association closes a Setup bookkeeping consumer of existing real effects;
it is not the runtime pilot gate. The credential-controlled native request path
still needs its actual required endpoint families/driver/cleanup joins completed
where unavailable, independently assigned keys/configuration/grants and installed
immutable runtime artifacts. The exact connected source must then be built and
exercise the authorized request plus a denial, authentic returned response and
unknown/recovery behavior against those actual owners.

Native request/runtime and raw hardware/proxy evidence still need their explicit
protected Setup receiving successors; CA readback, local captures and this
association cannot substitute for them. The independent final Setup authority
must consume real native completion inputs through its own fixed purpose before
any final completion claim. Existing legacy final APIs expect a different
enrollment capability/receipt identity and cannot be made native by copying
status fields. Those are remaining code/provisioning integrations, while the
first build, deployed custody, independently operated authorities and exercised
end-to-end evidence are runtime/deployment gates. No date or pilot acceptance
follows from this source slice. No tests, builds, parsers, runtime, cloud or
signing actions were executed for it.
