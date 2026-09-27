# Preparing finalization from retained registration originals

[`control_plane_registration_finalization.prepare_retained_registration_finalization`](../serverware/control_plane_registration_finalization.py)
adds a separately authorized **preparation** facade. It does not finalize a
credential or report registration success. This source is unbuilt and
unexecuted; it is not deployment or production acceptance.

The API is `prepare_retained_registration_finalization(local_digest, *,
expected_user_id, expected_session_id)`. The real application must first admit
the present finalization-preparation purpose, current user/session and applicable
MFA/two-person/CSRF requirements. Supplied expected scalars must come from that
actual authentication, not posted subject metadata or old approval claims.

It returns exactly `(local_digest, finalization_local_digest)`:

- The first is the unchanged input registration-execution/evidence-admission
  raw10 locator. No legacy evidence raw6 record or digest is manufactured.
- The second is the actual durable local locator of prepared
  `webauthn.registration.finalize` transition raw7 originals.

Neither ID is a credential, active-session result, remote receipt, currentness
lease or permission to execute/retry.

**This remains preparation only:** this path does not
issue dedicated finalization execution authorization. The actual grant preserves
the signed plan's original issue time and rejects a caller authorization issued
later. Today's raw7 therefore cannot gain fresh execution permission afterward.
The separate grant path admits its own caller/purpose, reconstructs the exact
request and issues dedicated authorization **before** producing a new live plan
and grant. Reservation and execution remain separate. Backdating, retiming and automatic
replanning are forbidden. See [original execution admission](registration-finalization-execution-admission.md).

A separate [grant preparation route](public-registration-finalization-grant.md)
now invokes `prepare_and_retain_registration_finalization_grant(local_digest, *,
expected_user_id, expected_session_id)`. It shares the genuine retained
ownership/completion preflight, then uses the dedicated cold caller to authorize
before one new plan and same-read complete vector, obtains and verifies the
dedicated grant, and retains exact authorization/raw7/vector/grant as raw10.
It returns `(existing evidence locator, actual finalization grant locator)`.
The older private `prepare_authorized_retained_registration_finalization`
still returns authorization/raw7 in memory; neither it nor the original
preparation-only route silently upgrades to this durable grant path.

The [journal's distinct finalization profile](control-plane-custody-journal.md#associated-finalization-grant-preparation)
uses `SWCPF001` and a last-published `SWCPM001` association binding that new
record to the existing evidence-grant/signer pair. It rereads the originals,
preserves their IDs and rejects conflicting or cross-source linkage. Missing
final association means incomplete local preparation, not permission to infer
success or retry. This association supplies no cryptographic replay or
execution authority.

## Required retained state and verification

Both actual cold enrollment/custody owners and their original attestation must
remain valid under the independently configured cohort. The exact durable
association must identify the current-source grant raw10 and signer
request-eight/response-two. The journal must already retain a reservation, an
SQL dispatch claim and an **acknowledged** completion, either the original
completion record or its separate immutable reconciliation record.

Missing or uncertain completion fails; preparation never calls recovery, sends
another completion request, or dispatches evidence SQL. A local state label or
association does not establish authentic completion or user ownership.

The facade holds all originals and their existing body/group bounds, with a
combined 64 MiB ceiling including the three enrollments, before subsequent
verification callbacks. It then:

1. Runs the genuine **live** retained-subject replay and signer/grant request
   commitment join. The replayed user and optional OIDC session must equal the
   independently authenticated current caller scalars.
2. Re-verifies the stored completion originals through actual live
   planning/caller/grant admission and genuine pending/completion/state replay.
   Pending sequence/head/fence come from the independent cold configuration,
   never from the response or journal state.
3. Calls the existing [live finalization preparation](registration-finalization-preparation.md)
   using those exact signer originals. It replays the original ceremony and
   evidence, performs the bounded sibling-selector lookup where needed, and
   sends original bytes to the actual finalization verifier/planner/custody
   path. Sibling IDs are lookup hints, not complete-population proof.
4. Durably appends the returned real transition raw7 without forwarding it.

The actual transition planner must still prove current challenge/history and
complete siblings plus an unconsumed, committed v2 evidence row at its real
planning cutoff. A signed completion or retained custody record does not
substitute for those database proofs.

## Lifetimes and remaining execution boundary

The facade creates one current cumulative work allowance/window. Its private
continuation passes that same work and original window to the narrowly factored
`_prepare_registration_finalization_on_work`; inherited bounds may only shrink.
The older standalone `prepare_registration_finalization` signature/output is
unchanged. Repeated genuine replay consumes the same work and may exhaust it;
no successful carrier or fresh allowance skips a gate.

Historical completion recovery does **not** bypass live signer, evidence,
caller/grant or finalization admission for new credential effects. Expired
originals fail this preparation path even when historical recovery successfully
authenticated an old completion. As in the existing preparation API, an opaque
durable append may finish after the preparation window; that retains bytes
without renewing any authority.

Dedicated caller admission, authorization-before-new-plan, grant transport and
durable linked retention are now implemented in the separate source-only grant
flow. Independent reservation, actual atomic credential finalization and
outcome handling remain required.
OIDC browser-session activation is a separate operation, not an effect of the
registration-finalize kernel.
This facade does not invent or call missing execution authority. A response
may say `prepared`; it must not claim registration completed, session activated,
currentness established or automatic retry allowed. Production verification
and independently provisioned services remain outside this source batch.
