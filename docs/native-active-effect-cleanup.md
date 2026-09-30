# Native active-effect cleanup authority

This source owner supplies the missing CleanupAuthorizationConsumer half of
the active-effect path. It is not a business-effect executor, a generic signer,
or evidence that an ordinary request has run. Build, installation, independent
grant approval, launch and end-to-end execution remain unperformed.

## Actual caller and key boundary

`services/active_effect_cleanup.rs::Gate` is retained beside the real cleanup
service and its existing generation gate. The source-selected ordinary runtime
is `serverware.policyCustodyServiceRuntimeConfig/v8`, with `spoolCleanup` equal
to the closed object `{"grantFdName":"active-effect-cleanup-grant"}`. The
ordinary service's authenticated session and generation admission must run
before `Gate::handle`; there is no direct HTTP or arbitrary signing route.
The bridge verifies the exact grant through `Grant::verify` against the real
cleanup session's current authority history before its first effect command.

The real `TrustedHostNoTeeCleanupAuthorizationConsumerServer` retains its
existing independently assigned key. Its only new method accepts the opaque
`active_effect_cleanup::Input`; only this gate can construct that input. This
does not rename the ordinary host service into an enclave key owner or grant it
any native role key. Native barrier/commit, retrieval, cleanup and durable
allocation keys remain distinct.

The bridge sends canonical `serverware.nativeActiveEffectCleanupCommand/v1`,
exactly `{apiVersion, completion}`. `completion` is the actual typed
`active_effect_values::Completion`, not a supplied success boolean. The reply
is exactly the typed `{result, transition}` `Cleanup` value. Frame handling,
the runtime option, module registration and bridge caller belong to the
paired active-effect implementation; this slice does not replace those joins.

## Independently approved originals

The C9 activation inventory supplies a final-role-owned, fully sealed 0600,
zero-link `active-effect-cleanup-grant` memfd (at most 128 KiB) and an exact
retained `active-effect-cleanup-journal` directory. The grant is the existing
canonical envelope `{payload, signatureBase64url}`. Its payload has exactly:

- `apiVersion`: `serverware.nativeActiveEffectCleanupGrant/v1`;
- `purpose`: `native-active-effect-cleanup`;
- `guest`: the actual Cleanup C9 `GuestClosureBinding`;
- `runtimeConfigurationSha256` and `authorityHistoryManifestSha256`;
- `headGrantOriginal`: the entire canonical ASCII v3 shared-spool grant;
- `durableAuthorityEpoch` and `durablePublicKeyBase64url`;
- `initialTransitionHeadSha256`.

The independently provisioned cleanup root signs the payload with the existing
protocol framing and domain `serverware.nativeActiveEffectCleanupGrant.signature/v1`.
This explicitly authorizes the whole head original and DRS allocation key;
the code does **not** claim that the cleanup history verifies the DRS history
or the head grant's separate signature. The real DRS itself admits that head
grant. Each later allocation must carry the exact head-original digest, pinned
DRS epoch and genuine DRS signature. Same boot/time namespace, original scope
window, role-separated keys and actual cleanup current epoch/key/head are
required. No key, grant or replacement history is generated here.

## Durable permit and one-use consumption

Before sealing a barrier, the gate checks the original dispatch scope, DRS
allocation signature, independently signed native preparation/completion and
signed storage receipt. The real cleanup owner then signs the existing
`ActiveEffectPermit` material and its own linked service transition. Exact
request plus reply are appended, fsynced and read back by the existing bounded
durability worker before any reply leaves the gate. The original owner state
and original operation deadline are checked again after durable completion.

The retained journal reconstructs the issued barrier set and consumed set.
Commit and Reconcile require the full prior barrier to equal the gate's own
journaled original; a caller cannot introduce a permit by uploading one. A
particular effect is issued once and consumed once, including an
`OutcomeUnknown` or `ReconcileRequired` terminal record. Reconciliation records
the signed requirement to reconcile; it never upgrades uncertainty to a
business success. Duplicate operation/replay identities refuse. There is no
new retry, reset, repair or deadline-renewal API.

The exclusive journal owner uses the no-orphan-repair profile, at most 128
records and 64 MiB of retained history. An uncertain write or changed original
poisons the live gate; an orphaned restart is refused. A definite journaled
record after reply loss remains consumed, not permission to repeat the effect.
These fences do not prove remote business completion and do not replace
existing PIDFD/lifetime or independent protected-policy owners.
