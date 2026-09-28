# Dedicated cold release-intent caller

Parent enrollment bootstrap `/v9` adds nullable `oidcSessionActivationReleaseIntent`
under distinct `serverware.signedControlPlaneEnrollmentBootstrap/v9` and
`serverware.controlPlaneEnrollmentBootstrap/v9` schemas. Versions v2–v8 keep
their closed parent shapes. The whole parent remains capped at 4 MiB. V9
reserves FD207 even when the new lane is null; issuer/bootstrap collisions,
inherited disabled slots and undeclared open slots fail closed.

The nested `serverware.controlPlaneOidcSessionActivationReleaseIntent/v1` has
exactly four fields:

- `schema`;
- `callerPrivateKeyFd`, exactly 207;
- `intentEnrollment`, exact `{base64Url, byteCount}` canonical original, at most 16 KiB;
- `expectedScope`, the independently root-pinned six fields `configurationDigest`,
  `databaseId`, `generationDigest`, `runtimeClosureDigest`, `callerId`, and
  `receiverIdentity` (the existing exact three-digest identity grammar).

It requires actual activation planning and explicit consume execution `/v4`.
That consume version has exactly the `/v3` fields; only its source-selected
immutable material flag `release_hints` is true. Older versions retain false
and their original transport behavior. No posted boolean selects this profile.

## Genuine enrollment and separate key

The mapper holds original/key references and owns the complete configuration,
generation, runtime and intent-scope graphs before native admission. On the
same work it reauthenticates the actual current-root and consume-grant
enrollments, and the original root-signed activation planner bootstrap. It joins
the actual configuration/generation/runtime cohort, database and runtime
closure to the independent intent scope. Planner cold freshness creates no
request permission or new request allowance.

Actual intent-enrollment admission authenticates its root signature and exact
scope, public-key binding and policy. The signer is separate from root,
activation/consume planner and caller keys, independently enrolled computation,
completion, state and consume-grant authorizer keys, and optional retained
issuer/registration/finalization callers. Unique actual public SPKIs form the
bounded exclusion tuple; all configured role-response, evidence, transition
and enrollment pins are checked separately. Startup additionally excludes the
actual HTTP response key and retained private purposes. The later proof
enrollment must still enforce its own intent-key exclusion.

The stdlib entrypoint recognizes only this closed data shape and imports no
repository cryptography. Its new fixed helper reads only already-provisioned
root-owned mode0400
`/run/secrets/serverware-oidc-session-activation-release-intent-key`, then uses
the existing sealed, no-follow, non-overwriting purpose delivery at FD207.
The independently signed runtime inventory must include the enabled slot.
No key, user, directory, socket or permission is created.

Actual UID/GID65532 startup reads the admitted sealed key, reserving its actual
bounded size before the native read, verifies unencrypted Ed25519 PKCS8 and
the genuine enrolled pair, and keeps descriptor/receipt continuity. It stores
`_intent_key`, `_intent_key_fd`, and `_intent_key_identity`; shutdown drops the
key reference without closing borrowed descriptors. Disabled issuer policy
does not force a reused signer. Caller/receiver measurement labels remain
trusted-host-local root assertions, not hardware or observed process proofs.

## Interfaces and authority boundary

`_ReleaseIntentMaterial` has exactly `caller_private_key_fd`,
`caller_public_key`, `enrollment_bytes`, `enrollment_digest`,
`expected_scope_bytes`, and `forbidden_public_keys`. `_scope_on_work` reads the
canonical retained scope; it does not authenticate a new authority. Parent
material appends `release_intent=None` and `intent_slot_reserved=False` for
older versions. `release_intent_enabled` reports cold configuration only.

The no-argument `_authorize_oidc_session_activation_release_intent()` facade
selects this parent's actual active permission and calls its one-use
`authorize_release_intent()`. The real coordinator must preserve the original
work/window/deadline and current old-token possession, re-admit the enrollment,
and derive its target from the retained same-context originals. Signing an
intent neither establishes committed consumption nor opens an AES key.

There is deliberately no future `expectedRelease`, intent digest, request
identity or outcome identity in this cold lane. Existing release-client
configuration is not a pre-intent authority: its embedded release custody
already pins `releaseIntentDigest`, and its client scope pins future request
and outcome identities. Consume-completion digest hints can select a candidate
intent binding only as unsigned data. The later genuine private proof must
independently recompute and verify every binding; the signed intent cannot
launder hints into committed evidence. No new root target grant is introduced.

This is source-only integration, unbuilt and unexecuted. It does not finish
protected handoff, authorize a token/cookie response, prove a current session,
or advance production acceptance.
