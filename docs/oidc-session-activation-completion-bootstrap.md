# Activation completion launch admission

This dedicated bootstrap is **source-only, unbuilt, unexecuted and unprovisioned**.
It admits a fixed completion launch, not a successful replay token, installed
service, public permission, current browser session or token-release capability.
It composes the [historical receiving bootstrap](oidc-session-activation-history-custody-bootstrap.md)
with the actual [completion/recovery library](oidc-session-activation-completion-recovery.md).
F08.4e.6 remains partial until its complete named integration is landed.

## Originals and independent scope

The closed schemas are
`serverware.signedOidcSessionActivationCompletionBootstrap/v1`,
`serverware.oidcSessionActivationCompletionBootstrap/v1` and the nested launch
`serverware.oidcSessionActivationCompletionLaunch/v1` or explicit `/v2`.
The operation is `oidc.session.activate`; the sole role/process mode is
`oidc-session-activation-completion`, UID/GID **65503**, with request peer
**65532**. Other receiving roles are not widened.

The nested launch versions have the same closed fields and resource inventory;
their root-signed schema selects one request grammar before receiving. Launch
v1 stays strictly the original packet-selector profile. Launch v2 selects the
separate [dispatch profile](oidc-session-activation-completion-dispatch-transport.md):
fixed purpose plus the exact signed caller authorization original. The service
must compare those bytes with its genuinely admitted root-held original, then
use only its own independent packet pin. No request-selected fallback, unsigned
SQL authority, public AES custody or returned packet-identity claim is added.
Neither version skips actual private historical replay or starts a new
processing allowance after request reads.

The root signs the exact canonical outer bytes. Its payload embeds the genuine
historical-custody original, not previously returned material. That original
authenticates a fresh historical receiving purpose and the genuine original
planner configuration, policies, keys, vector and state enrollment. The launch
independently pins and joins receiver identity, configuration/generation/runtime
closure, database identity, caller/state/grant enrollments and the original
caller authorization. The completion key and measurement come from the actual
root-authenticated state enrollment, with purpose-key separation. The independent
receiver measurement must match that enrollment; these are root assertions, not
proof of a measured runtime.

The caller authorization's real signature, canonical original, enrollment,
request/operation/journal/vector identities and original interval are checked.
It may be expired. This limited bootstrap admission does **not** claim to replay
the absent encrypted plan or effects: genuine original plan, reserve, snapshot,
ACK and committed-marker/full-vector replay remain mandatory in the completion
composition. The root-held packet and authorization digests, exact
`{request, scope, journalDigest}` expectations and current-pending
`(sequence, headDigest, fence)` never come from an unsigned SQL response or ACK.

The separate `(sequence, headDigest)` completion checkpoint is capacity checked;
its zero-sequence head must be the genuinely admitted enrollment identity.
Retained files cannot select their own expected checkpoint. Source/configuration
cohort checks remain strict; cross-version historical authority is still H05.

## Fixed cold resources

| FD | Original resource |
| --- | --- |
| 198 | Root public key |
| 199 | Signed completion bootstrap, including historical custody |
| 200 | Listener `/run/serverware/oidc-session-activation/completion.sock` |
| 201 | Actually enrolled completion signing key |
| 202 | Journal directory `/var/lib/serverware/oidc-session-activation-completions` |
| 203 | Independently pinned bundle AES key |
| 204 | Independently pinned delivery AES key |

The exact seven-descriptor inventory, listener/socket and directory device/inode
pins, fixed paths, service/request-peer IDs, timeout and journal record bound are
root signed. There is no extra custody FD, caller/planner/grant signing key or
fallback environment secret. The historical original pins separate AES keys;
their bytes are never serialized in the bootstrap.

Two actual read-only database configurations are derived as immutable tuples:
`(dsn, timeout, role, clientDn, clientSerial, issuerDn, queryDigest, structureDigest)`.
Their roles are the fixed successor-custody recovery and completion-commit
reader roles. The DSNs use one closed literal endpoint, `verify-full`, fixed
certificate/key paths and no password or caller-supplied DSN. Both query and
structural-catalog pins must be consumed by the actual reader owners. Matching
endpoint/TLS fields alone do not prove same-database provenance.

The five pinned files under `/run/serverware/oidc-session-activation-completion-tls/`
are `ca.pem`, `custody.crt`, `custody.key`, `commit.crt` and `commit.key`.
Certificates/CA are bounded at 64 KiB each; keys at 16 KiB each; minimum is two
bytes. The fixed state endpoint is `/run/serverware/current-root/state.sock`:
state service UID/GID 65516, root-activated listener peer 0:0. Separate signed
state-peer admission and narrowly provisioned socket access remain necessary.

## API, bounds and time

The private verifier is:

```text
_verify_on_work(*, bootstrap_bytes, root_public_key, work,
               live_window=None, transport_deadline_ns=None)
```

The source producer replaces `bootstrap_bytes` with `payload` and
`root_private_key`, retaining the other keywords. It owns the bounded payload
before clock/key callbacks, genuinely admits its originals, checks the actual
root key pair, then signs and verifies in the distinct domain.
`_fresh(interval, work, opening=None)` is for fresh role/custody intervals only.

The outer bound is **16 MiB**, with a genuine embedded custody original bounded
at **8 MiB**. The decoder and canonical capture use those actual limits and the
same cumulative work ledger, not the older 4 MiB bootstrap decoder. Original
inventory remains bounded by the existing 64 MiB ceiling; replay expectations
retain their own smaller source bounds. No replacement work is opened.

A supplied current window and absolute transport deadline are preserved. The
cold-only optional form takes one real opening sample before decoding and uses
the fixed source maximum processing age. Subsequent policy/launch narrowing
retains its original epoch and monotonic samples. The fresh launch interval is
at most 300 seconds and must fit the independently signed fresh historical
custody interval. The old planner interval is only an algebraic original bound;
it never enters `_fresh`, processing expiry or a substituted old clock.

The frozen `_CompletionMaterial` carries owned original bytes, genuine same-call
historical material, independently joined key/configuration/enrollment scope,
caller age/skew, pending/checkpoint tuples, expected packet/authorization and
request scope, the two reader tuples, TLS pins and original launch bracket.
No authority entrypoint accepts this material instead of original verification.

All five hardware/TEE/HSM/witness assurance flags remain false and trust mode is
`trusted-host-local`. This module opens no resources and supplies no off-host
rollback/currentness assurance. Dedicated delivery, actual service construction,
state-peer admission and response verification must join these originals; generic
activation completion APIs remain rejected rather than acquiring a history
bypass. Public activation/recovery, protected token release and portal/current-auth
confirmation remain separate work. No build, parser, interpreter or runtime
verification was performed.
