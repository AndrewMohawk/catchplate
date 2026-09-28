# One-shot consume-input issuer service

`oidc_session_activation_consume_input_issuer_startup` owns one private issuance
exchange after genuine root delivery and permanent UID/GID `65495` drop. Its
runner continues the original work meter, opening window, absolute deadline
and actual delivery guard; running the runner directly fails closed.
This is source-only implementation, unbuilt, unexecuted and unprovisioned.

## Fixed custody and admission

The service inherits exactly six independently delivered resources:

| FD | Original resource |
| --- | --- |
| 198 | Runtime root public key |
| 199 | Signed issuer launch bootstrap |
| 200 | Root-created consume-input `grants.sock` listener |
| 201 | Independent signed consume-input issuer policy |
| 202 | Policy-pinned historical activation planner bootstrap |
| 203 | Runtime root private signing key |

Startup re-admits the actual launch, policy and historical planner originals
before reading the private key through the real delivery helper. The key must
match the runtime root. No AES, private history, completion signer, database
connection, worker-resource channel or journal is opened by this owner.

Original process/PID, closed environment, permanent credentials, immutable
configuration references, sealed descriptors and listener pins remain checked.
Only the actual accepted, peer-checked socket may extend the inherited
inventory. A replacement descriptor or unrelated socket is never exempted.

## One exchange on the original allowance

`serve_once()` spends its irreversible in-process latch before readiness or
accept. The kernel peer must be UID/GID `65532` before any request bytes are
read. The exact fixed transport request is raw17: source purpose followed by
the [original producer's raw16](oidc-session-activation-consume-input-production.md).
No incoming policy, resource pin, root key, callback or successful admission
carrier can replace the independently inherited originals.

Before body allocation, the native header must fit a tightening request cap
computed from the actual held cold/decoded/wrapped original inventory, both
output originals, derived payload reservation and framing within 64 MiB.
The signed request timeout is applied once to the original opening. Policy
and deterministic output expiry, maximum age and skew can only shorten that
same allowance; accept, parsing and signing never open a new one.

The service invokes the genuine original-only producer once with the exact
raw16 suffix, held independent policy/planner originals and actual root key
pair. Nested admissions and signing retain sticky epoch/monotonic floors and
the same cumulative ledger. The private continuity seam exchanges restrictive
clock floors only; it conveys no permission or replacement processing scope.

Only the actual signed planner/history raw2 is framed back to the original
peer. The live owner guard remains active through send and normal socket
close. Success means this finite exchange closed normally, not that a consume
worker started, private replay passed, SQL committed or a credential arrived.

## Failure and remaining boundaries

Any failure is terminal: no retry, second accept, fallback signer, invented
error response or renewed allowance. The runner emits only fixed generic
failure text, never original request data or exception details. Old-token
possession remains ephemeral; this service does not journal or log it.

Cleanup makes one attempt only against each held original descriptor identity.
An uncertain accepted-socket close is quarantined and remains a failure;
cleanup never closes an identity-replaced descriptor or silently reports
success on a later attempt.

Signed consume-worker resource pins remain authorization, not observations of
provisioning. The service does not stage planner/history originals into a
worker, deliver AES keys, provision resources or claim private worker readiness.
Actual consume-worker delivery and its proof/current-row checks remain separate
requirements. No public route or completion/release authority is added here.

The checked-in socket unit and service template are uninstalled and unrendered.
`Dockerfile.production` packages their source and the isolated launcher only.
The optional `docker-compose.oidc-session-activation-consume-inputs.yml` exposes
only the already-provisioned fixed public `grants.sock`, read-only, with host
path creation disabled. It mounts no signer, policy directory or AES material;
the base Compose file is unchanged. None of these source definitions performs
installation, provisioning, worker staging or a production acceptance check.
