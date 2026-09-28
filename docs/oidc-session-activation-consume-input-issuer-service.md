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
connection or journal is opened by this owner. Explicit signed launch v2 adds
one fixed public-original staging channel, not private resource custody.

Policy v2, independently of launch v2, carries the current-root-signed historical
bridge and wrapped current output planner. The existing FD202 retains its old
planner meaning; no descriptor, producer argument or received material object is
added. The original-only producer re-admits the policy and uses its independent
historical root only for old controls, while the inherited current root key pair
signs new output. V1 retains its same-context behavior and 64 KiB policy limit;
v2 permits at most 6 MiB before the combined limits tighten it further.

Original process/PID, closed environment, permanent credentials, immutable
configuration references, sealed descriptors and listener pins remain checked.
Only the actual accepted, peer-checked socket and the v2 owner's actual single
staging socket may extend the inherited inventory. A replacement descriptor or
unrelated socket is never exempted.

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
The pre-body cold reserve includes eight actual sealed-original footprints plus
the shared producer cold-derivation reserve, output and both wire headers. Only
one eighth of the remaining bytes is available to the request body, so request
captures cannot obtain a separate 64 MiB allowance. Both old and current decoded
planner/state/vector representations must fit the already held reserve; only an
identical v1 planner object is deduplicated. These are source-accounting bounds,
not heap/RSS measurements.
The signed request timeout is applied once to the original opening. Policy
and deterministic output expiry, maximum age and skew can only shorten that
same allowance; accept, parsing and signing never open a new one.
The deterministic new-output interval comes from the admitted current planner;
historical and current age/skew constraints both remain restrictive.

The service invokes the genuine original-only producer once with the exact
raw16 suffix, held independent policy/planner originals and actual root key
pair. Nested admissions and signing retain sticky epoch/monotonic floors and
the same cumulative ledger. The private continuity seam exchanges restrictive
clock floors only; it conveys no permission or replacement processing scope.

Under launch v2, the actual signed planner/history raw2 first goes to the fixed
root staging endpoint. Request originals, including old-token possession, are
not sent to that receiver. The issuer reserves the retained/output wire bytes,
frames and ACK within 64 MiB, spends a separate one-use staging latch and owns
the socket from creation through normal close. Only a raw3 staged ACK matching
both purpose-separated original identities permits returning the original raw2
to the public caller. The receiver's separate verification and actual resource
checks are described in [dynamic delivery](oidc-session-activation-consume-dynamic-delivery.md).

Launch v1 has no staging channel and retains its existing return behavior. The
original guard remains active through both exchanges and normal close. A staged
ACK is not worker readiness, private replay, SQL commit or credential delivery.

## Failure and remaining boundaries

Any failure is terminal: no retry, second accept, fallback signer, invented
error response or renewed allowance. The runner emits only fixed generic
failure text, never original request data or exception details. Old-token
possession remains ephemeral; this service does not journal or log it.

Cleanup makes one attempt only against each held original descriptor identity.
An uncertain accepted or staging socket close is quarantined and remains a failure;
cleanup never closes an identity-replaced descriptor or silently reports
success on a later attempt.

Signed consume-worker resource pins remain authorization, not observations of
provisioning. The v2 staging path delivers only the exact public originals; this
issuer never delivers AES keys, provisions resources or claims private worker
readiness. Genuine worker proof/current-row checks and actual deployment remain
separate requirements. No public route or completion/release authority is added.

The checked-in socket unit and service template are uninstalled and unrendered.
`Dockerfile.production` packages their source and the isolated launcher only.
The optional `docker-compose.oidc-session-activation-consume-inputs.yml` exposes
only the already-provisioned fixed public `grants.sock`, read-only, with host
path creation disabled. It mounts no signer, policy directory or AES material;
the base Compose file is unchanged. None of these source definitions performs
installation, provisioning or a production acceptance check. The separate opt-in
issuer staging drop-in is required only for launch v2 and leaves v1 packaging
independent of the dynamic receiver.

This bridged intake does not open the public archived-effects gate: the lower
delivery-plan historical-authority join remains separate. No retry, old-expiry
renewal, current-session result or production acceptance is established here.
