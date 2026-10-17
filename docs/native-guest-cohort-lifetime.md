# Native guest cohort lifetime and startup v10

`catchplate.nativeStartupConfiguration/v10` adds required `guestCohort` to
the exact v9 measured-issuance configuration. It is selected only by
`--native-guest-cohort-startup-v10`, or `--guest-cohort-v10` on the fixed native
image entrypoint, with the existing independently pinned configuration and
launch artifacts. The entrypoint also exposes the explicit v9 selector
`--measured-issuance-v9`. All earlier startup profiles retain their own selectors
and pass no cohort; they cannot acquire one by including extra fields.

The v10 object retains measured issuance, refresh, audit, broker/currentness,
the inspector and the original encrypted service-token envelope. All six
plaintext bearer fields remain explicitly null. Guest response-client admission
comes from the actual pending encrypted-service-token source, not an inferred
version string. Guest inspection and the explicit guest response listener are
mandatory; failed guest startup cannot fall back to host custody.

## Actual owner sequence

The original native lifetime owns one root `Prepared` privilege transition.
That exact preparation first launches and retains the initialized inspector,
then supplies the same inspector owner to `StartedGuestCohort::launch`. The
cohort factory consumes its one-use router endpoint internally and re-admits
the seven independently signed role deliveries. Its existing order remains:
state-authority listening after genuine bootstrap, five dependency listeners,
router, then every genuine role `started` publication. Passive progress never
substitutes for the existing generation/backend/quote or service-readiness
checks. See [the cohort contract](native-guest-cohort.md) and
[the child contract](response-v2-guest-role-startup.md).

The returned cohort is attached to the same unique native lifetime before any
further startup operation. NSM and broker preparation then finish under that
original root owner. Permanent gate privilege drop binds the actual final
serving owner, and both cohort and inspector must match it. Genuine shadow and
response-v2 client initialization still runs after this startup sequence, before
serving. No old process identity is rebound and no timeout is restarted.

During serving the lifetime checks the actual cohort, inspector, retained
originals and final privilege owner. Failure requests stop for every role first.
The inspector stays available while roles drain. Explicit cleanup calls the
cohort's real `stop_and_reap`, then the inspector's real `stop_and_reap`; an error
from either is reported, and inspector cleanup is still attempted after a role
error. One cached cleanup outcome joins the runtime and outer startup paths,
including ordinary early errors. Drop only requests best-effort cancellation;
it does not certify reaping. A partial cohort launch remains owned by the
factory's own stop-all/reap guard.

## Provisioning and evidence boundary

This is source integration, not an executed enclave, complete provisioner or
pilot. The signed configuration/delivery originals, exact final-role `0400`
credential files, protected runtime directories, real fresh generation TEE
verifier and actual durable state backend must already satisfy their consumers.
The [public generation layout](response-v2-guest-public-artifacts.md) and
[authenticated ledger reads](response-v2-ledger-exact-read.md) supply separate
explicit profiles for cross-UID metadata and committed-byte retrieval. Neither
relaxes private `0700` state directories or grants DAC capabilities. The actual
raw-response persistence and state-commit producer remains required; a readable
ledger does not prove that original responses were captured or stored.

In particular, the gate's KMS broker is bound only after permanent drop and
actual enclave identity admission, whereas role startup needs its assigned keys
before that point. This profile does not treat prepared broker state as a
provisioned key owner. A separately authorized boot-provisioning path or a
genuine phase change is required; no key material or fresh boot authorization
may be baked into an EIF or invented from missing files. Host UDS identities
and persistent-database assumptions are not reinterpreted as vsock evidence.

No builds, tests, parser execution, provider contact or runtime verification
accompany this source checkpoint.
