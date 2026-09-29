# Current credential leases through the actual control-plane API

This joins the [measured-holder barrier](credential-currentness-holder-barrier.md)
to the existing HTTP lease endpoint and controlled OAuth refresh client. It is
source implementation, not a built or exercised pilot.

## Admission and original requests

The actual configured control-plane custody selects strict currentness. It does
not depend on an incoming version, successful diagnostic or new environment
switch. A configured owner refuses bare legacy, policy-aware and native leases;
there is no downgrade after failure. Only independently unconfigured development
retains the old request path. Existing credentials without a never-issued root
require explicit migration, not automatic admission based on absent records.

The existing bounded JSON reader authenticates the data-plane credential-lease
token before reading at most 96 KiB. It rejects duplicate keys and nonfinite
numbers, validates a closed versioned model, and retains that model's complete
original parsed dictionary on the actual request scope. The currentness owner
receives this original inner request, not reconstructed model output or a
synthetic HTTP request. Fields inside the original recipient attestation and
release authority remain in the holder-signature commitment.

The [new request schema](../schemas/native-current-credential-lease-request.v1.schema.json)
wraps unchanged native v1/v2 requests. Metadata carries null currentness. Secret
dispatch carries the registered holder ID, exact epoch, registration digest and
dedicated Ed25519 binding signature. The independently registered key verifies
the complete original recipient request. Holder possession alone is insufficient.

Both strict routes require an exact POST path, no query and one valid original
`X-Serverware-Response-Nonce` before effects. The existing ASGI signer authenticates
the actual final response bytes and request context; these routes do not create
another signer or accept caller-provided response evidence.

## Metadata, refresh and secret release

Controlled OAuth refresh occurs before metadata pins a version. Refresh now
requires the genuine all-holder drain barrier before its fixed claim, and the
claim includes its exact `currentnessBarrierSha256`. Waiting spends the original
contact and retention windows; it does not renew them. A missing acknowledgement
or expired operation refuses the effect and cannot reopen the old epoch.

Metadata returns only the current version, epoch and root digest. The native gate
must then genuinely register that returned version before requesting its secret.
Dispatch verifies the current protected root and recipient-binding signature
before nonce/release claim and secret preparation, repeats that check against
the selected credential snapshot, and checks again after encryption and issuance
audit. Strict managed OAuth dispatch cannot enter legacy automatic refresh when
the actual enrolled refresh owner is absent.

The [response wrapper](../schemas/native-current-credential-lease-envelope.v1.schema.json)
contains the existing encrypted native envelope with unchanged AAD and plaintext
profile. A metadata context is data only; a dispatch response echoes its exact
original signed pin. Final output retains the existing 8 MiB bound and no-store
policy. Repeated control-plane checks do not themselves establish atomic network
revocation: the native gate's registered-holder send guard and irreversible drain
prevent late responses from restoring old cache authority.

## Public phases and remaining work

The [public phase request](../schemas/credential-currentness-request.v1.schema.json)
uses `/api/data-plane/credential-currentness`, the same transport token and a
64 KiB body bound. It exposes challenge, register, ack and SELECT-only poll.
Quiesce and admit remain private actual refresh/cleanup-owner operations. There
is no public reset, holder deletion, barrier reopening or timeout-as-absence path.

The separate [refresh-cleanup worker](oauth-refresh-cleanup.md) is cold-admitted
after exchange revocation and before HTTP startup, and closed first on shutdown.
Startup rechecks its actual owner before workers begin. Reconciliation runs both
independently selected controlled lanes with a per-lane limit of at most 16;
either selected lane prevents falling through to legacy mutation. Their combined
counts describe claims, accepted/rejected/unknown responses, no-contact outcomes
and blocked work, not a claimed number of provider-revoked credentials. Cleanup
needs its own current family-retirement grant; a drain barrier is not permission
to revoke a provider's token family.

Authenticated holder recovery, historical migration, retained-capacity lifecycle,
OAuth reconnect, measured full-proxy deployment and independent runtime acceptance
remain required. This source connection closes none of those requirements.
