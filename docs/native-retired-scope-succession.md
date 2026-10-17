# Native retired-scope succession

This source path implements the native half of the independently authorized
[append-only scope succession](oauth-retired-scope-succession.md). It does not
convert ordinary reconnect, a retirement receipt, possession of old ciphertext,
or an unknown provider effect into permission. Existing fences and consumed
attempts remain immutable. Source implementation is not build, attestation,
deployment, provider, browser or pilot acceptance evidence.

## Explicit cold selection and owners

`--measured-succession-v18` selects only
`--native-measured-succession-startup-v18` and the closed
`catchplate.nativeStartupConfiguration/v18`. It retains v17's actual native
service-token, currentness, role-cohort, inspector, cgroup and retirement owners,
but selects `measuredSuccession` instead of `measuredReconnect` and requires
`secretBroker/v2`. Older profiles keep their existing selectors and broker/v1;
neither incoming HTTP nor a nested marker selects succession. One actual
browser/helper purpose is installed, not several competing listeners.

`Configuration17` and historicalApplication3 retain their frozen contracts in
`native-oauth-retired-scope-succession.v1.schema.json`. The actual gate binds its
real identity, original boot/lifetime, independently assigned role-4 key and
the same `Arc<BrowserTls>` to the helper. Private configure is exact19: the
public17 fields, minus browserVsockPort, plus identity,
ingressLeafCertificateSha256 and ingressLeafSpkiSha256. The source-owned
`Prepared` value alone enters `sign_native_succession` with its own statement24,
schema-plus-NUL signature domain and separate NSM attestation domain. It is not
an arbitrary signing hook or a prepare-to-draft purpose alias.

The actual pre-drop `PreparedBroker` retains the opaque v2 inventory through
permanent privilege drop and binds to the same native identity and original
deadline. Serving tasks retain the startup lifetime and terminate through its
existing cancellation/shutdown ownership. The local OAuth serialization guard
prevents protocol interleaving; it is not family authority or drain proof.

## Historical custody and fixed provider effects

Broker/v2 is exact9: the existing eight fields plus `historicalKeys`, at most16
closed keyAssignment5 entries sorted by full KEK SHA. Full commitments and
derived IDs are unique, exclude the current key, and include exact KMS key ID,
ciphertext blob SHA and encryption context. The entire canonical inventory is
bounded at256KiB before the first contact. Current-key reuse is possible only
when the material genuinely names that same fully admitted key; there is no
current-key alias for missing historical custody.

`native_broker_history_kms_parent.py` accepts only its protected root-owned
exact5 configuration, <=512KiB, including the full v2 native original and a
sorted ciphertext inventory. It serves the one configured enclave CID/port and
fixed `/usr/local/bin/aws` call. Each genuine helper-generated RSA recipient has
fresh randomness and an actual native NSM quote: existing role6 for the primary
key, distinct role7 for historical keys. The quote commits the full original
v2 SHA, exact request/context/key/blob and recipient. KMS performs independent
attestation/release-policy enforcement; host correspondence parsing is not a
TEE verdict. A slot is consumed before its one KMS contact. Parent and gate
exchange ciphertext only, never unwrapped KEKs. Unknown responses abort native
startup rather than selecting another recipient or renewing the lifetime.

Historical keys remain inside the measured helper and establish custody only.
The noncopyable `ClaimedMaterial` is constructed from an actually authenticated
definite MATERIAL-CLAIM result under the same operation, source pin, scope,
nonce and original deadline. Only it can consume an exact key use. The full
token/application key IDs resolve to retained full commitments; no generic
decrypt RPC exists. Decryption occurs after the protected material claim, not
during INSPECT or recovery. Fresh issuance uses the one current target
enrollment, while old material is selected by exact historical enrollment SHA
and independently assigned `(holderId,enrollmentSha256)` pair, never provider
name alone. All historical application material, root/key, TLS PEM hash and
assignment joins are admitted before beginning historical effects.

Provider endpoints and encodings are source-fixed: Google revocation form at
`oauth2.googleapis.com/revoke`, X confidential-client Basic revocation at
`api.twitter.com/2/oauth2/revoke`. Frozen application3 does not contain the
provider-configuration preimage; the implementation does not fabricate one or
infer alternative custom-client modes. Each actual request's exact byte hash
is bound by CONTACT before the one TLS exchange. TLS roots come from that
exact admitted application's cold material, not the host trust store. Google
selects one refresh token when present, otherwise one access token; it does
not treat changed bytes as isolated-token revocation. X's permitted token
purposes remain separate consumed contacts within the independently authorized
family effect. An accepted-existing result must match the exact prior request
hash and token purpose and causes no POST. Independent external family scope
is still required; complete local inventory is not global provider ownership.

## One native browser handoff

The portal sends the canonical intent directly to the native origin as
`/oauth/begin#original=<unpadded-base64url>`. The fixed page clears the fragment,
keeps it only in memory and performs one POST after an explicit click. It does
not store assertions, private callback state or credentials, and never retries
an uncertain request. Before generating PKCE, the helper independently verifies
the root-signed authority configuration, full FENCE request and signed result,
original grant, immutable scope/journal/head, target and all affected lineage
drain associations. The controlled writer's current signed receipt remains
trusted-host-local evidence; it is not relabelled as TEE custody evidence.
Native role-4 evidence and independent effect roots remain separate.

Each bounded historical material follows INSPECT → MATERIAL-CLAIM → CONTACT →
FINISH, with accepted-existing bypassing only the new network POST. At most16
materials and32 contact slots are traversed in grant order under one original
begin interval. The gate's finite bound is98 replies, not a retry loop.
Every machine phase carries its own native purpose proof and receives an
independently verified signed result before advancing. Unknown contact or lost
acknowledgement cannot produce closure, new PKCE or a continuation grant.

Only exact accepted closure permits fresh same-account PKCE and one PREPARE.
Its public redirect is exact3 `apiVersion,exchangeId,location` with
`catchplate.nativeOAuthSuccessionAuthorizationRedirect/v1`. The private exact7
redirect additionally retains actual cookie fields and original expiry.
Rejected/unknown historical FINISH returns exact3
`catchplate.nativeOAuthSuccessionTerminalObservation/v1` with status
`retirement-rejected` or `retirement-unknown`; the scope stays fenced.

Callback claims once before the token POST, captures encrypted provider bytes
durably before same-account identity review, and stages a fresh envelope for
the authorized target credential/N+1. Target metadata's existing application
association is preserved. This is not synthetic Setup completion or automatic
credential activation. Explicit activation still requires its protected
current-scope/candidate/row joins; non-target fenced lineages are not reopened.

## Exact helper and recovery contracts

The concrete broker APIs are `configure_succession(config, Arc<BrowserTls>,
identity, boot, key, cpkey, binary, deadline)`, `succession_browser(&Accepted,
&relays)`, `succession_receipt(originals, &Prepared, deadline, &relays)` and
`recover_succession(id, originals, deadline, &relays)`. There is no public raw
descriptor, private-key export or caller-selected provider URL constructor.

Prepared reply exact6 contains apiVersion/phase/operation/arguments/issued and
expires. Complete exact5 contains apiVersion/phase/exchangeId/status and
custodyRowSha256 (null only before a fresh custody row exists). Private recover
exact5 contains apiVersion/phase/exchangeId/originals/deadlineBoottimeNs; its
originals are the frozen public recovery exact9. Recovery re-verifies originals
and emits exactly one RECOVER proof and observation. It cannot decrypt material,
resume cleanup, generate a nonce, POST, stage, clear a fence or reset history.

TLS event exact6 is apiVersion/providerId/purpose/sequence/ciphertext/read;
reply exact4 is apiVersion/sequence/ciphertext/eof. Only encrypted records cross
the parent, with one fixed socket per admitted contact,512 sequence steps and
512KiB total wire bytes. EOF/failure cannot reopen a socket. All COMPLETE
canonical frames—including encoded original receipts—remain <=8MiB. Smaller
2MiB configuration/arguments,3MiB HTTP request and original result bounds still
apply; a nominal field maximum does not enlarge the aggregate frame. Browser,
callback and recovery windows are clipped to the original signed admission,
contact, retention and native lifetime bounds, never renewed by a loop or UI.

## Source integration and acceptance boundary

The offline `scripts/package_native_broker_runtime.py` producer explicitly copies
the seven new native helper modules and the dependency-free succession catalog
into its existing sealed helper image. The actual helper imports the succession
owner and historical broker module; their portable imports resolve against that
fixed inventory and existing pure material/receipt validators, not control-plane
storage or authority execution modules. The existing deferred chroot import
check exercises that real helper import after packaging; it has not run here.
The existing file/hash inventory records these originals under the unchanged
aggregate file/image bounds, not a second runtime or new authority profile.

The history KMS parent remains outside the helper image. The actual top-level
`Dockerfile.production` already copies the whole admitted `/source/scripts` and
`/source/catchplate` trees into `/runtime/app`; this includes the new parent
script and its existing parent-side imports. The Make source inventories now
include that script and the seven helper modules (the catalog was already
registered with the control-plane prerequisite), plus all five new Rust files
and three schemas. No redundant Docker copy, independent parent runtime,
automatic service startup or KMS action is introduced by packaging. Source
cohort integration remains separate.
Fresh independent KMS policies, all historical ciphertexts/enrollments/roots,
actual measured release identities and purpose assignments must be provisioned;
schema validity alone cannot replace them. No build, parser, browser, provider,
cloud or runtime verification was performed in this source-only slice.
