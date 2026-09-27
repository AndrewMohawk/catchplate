# Private consume-planner service

The v2 source connects the [fixed OS delivery](oidc-session-activation-delivery-planner-delivery.md)
to the actual [cold planner](oidc-session-activation-delivery-cold-planning.md).
It is unbuilt, unexecuted and uninstalled. This is a private planning/retained
replay and exact encrypted-export service, not consumption execution, public
permission or token release. Earlier prepare/verify raw6 responses are preserved;
export is a separate fixed purpose and raw7 response, not an automatic chain.

## Startup and resource ownership

The child independently authenticates the original root/bootstrap/history bytes
delivered on FDs 198, 199 and 201. It accepts no parent success object. One
construction work allowance and actual epoch/monotonic bracket precede those
reads. Genuine admission narrows that same bracket to signed policy and the
outer/history interval; it never starts a replacement allowance after admission.

The exact environment, UID/GID 65501, empty supplementary groups, privilege
restrictions and eleven-descriptor inventory (198–208) must match the source
profile. The listener, journal and separate execution-store path/device/inode
identities must match signed originals. Sealed signer and four distinct AES-key
originals must match root pins; export key 207 cannot substitute for journal or
historical activation custody keys. Fixed
protected TLS files are bounded and measured on the same work allowance.

Only the real cold factory constructs the history custodian, read owner,
encrypted journal, first-exact execution store and retained plan owner. The
service holds their actual configuration identities and its own listener
duplicate. The inherited directory FDs 206/208 and both actual owners' duplicated
private directory FDs are checked against distinct signed pins and included in
the exact live descriptor inventory. Lifecycle checks
reject changed process identity, environment, sealed descriptors, listener,
journal/export directory, TLS metadata or held owner/configuration. These local controls do not
prove hostile-host isolation or off-host freshness.

## One accepted exchange

An idle poll may repeat only while the original construction lifetime remains
live. The launch ends after its first accepted connection, including an invalid
peer, malformed input, expiry, disconnect or uncertain outcome. The runner
always closes the service; neither runner nor unit automatically restarts it.

For that exchange, one request work allowance and current clock bracket open
before peer or body reads. Their deadline is clipped to the inherited launch
deadline and signed request timeout. The [fixed transport](oidc-session-activation-delivery-planner-transport.md)
checks peer UID/GID 65532 before reading a prefix. It reserves both headers and
the maximum response within the existing 64 MiB aggregate ceiling before
allocating request bodies, requires complete framing/EOF and performs no retry.

| Request | Actual operation | Token-free response |
| --- | --- | --- |
| Prepare raw15: purpose, original old token, activation raw13 | Cold owner's genuine acquisition, replay, signing and durable retention | `prepared`, request, scope, signed plan, plan digest, journal digest |
| Retained raw4: purpose, known envelope, independently held original deadline and journal digest | Known-signature admission, protected lookup and full original replay | `verified`, the same five original/locator fields |
| Export raw4: distinct export purpose, known envelope, independently held original deadline and journal digest | Actual cold owner's original-bound retained replay and first-exact encrypted export | `exported`, request, scope, signed plan, exact ciphertext bundle, plan digest, journal digest |

Callers cannot select policies, keys, roots, subject scope, paths or a different
operation. Those come from the root-admitted original configuration. Only an
actual `PreparedDeliveryPlan` may form a prepare/verify success response; export
requires the distinct actual `cold.ExportedDeliveryPlan`. No received result
object or raw identifier substitutes for the cold owner's original replay.
The service frames the actual same-call result without another full replay;
receiving ciphertext admission remains a separate unfinished boundary.
The original request clock bracket is further narrowed to the signed plan's
expiry for both epoch and monotonic checks through response transmission and
final return. Neither idle time nor response processing renews the launch.

If processing fails after request admission, the service may return only
`uncertain` plus five empty fields for prepare/verify or six empty fields for
export, and only while its lifecycle and original
processing bounds still permit a response. It may instead close without a
response. A durable append may already exist: neither outcome proves absence,
noncommit, rollback or permission to regenerate, re-sign, reseal or retry. A
failed export read never authorizes creating replacement ciphertext. The private
transport client returns unverified raw originals, not a proof-success or
execution capability.

## Remaining boundary

Closing the service closes its owned journal/export-store/history resources and listener
duplicate, drops references and ends the child. This is not a memory-erasure
claim. Root originals and protected inherited resources remain governed by
process exit and the independently operated launcher environment.

Image inventories and uninstalled systemd templates include the service, but
accounts, keys, immutable runtime, root-signed current configuration, separate journal/export store,
TLS/database access and state-v7 socket ACLs still require independent
provisioning. No service was started or production authority changed.

The committed caller-authorization foundations and this sender export are not
independent receiving custody/full proof replay or actual grant production/cold
receiving service. Those connections, reservation/current pending,
one-use SQL, completion/recovery, exact committed-original token release and
cold response/handoff remain open. Public permission and portal authentication
are separate remaining scopes. Source closure of this service checkpoint does
not close activation step 20 or any production acceptance gate.
