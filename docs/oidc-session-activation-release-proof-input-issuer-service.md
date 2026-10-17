# Finite proof-input issuer

Source integrated, unbuilt and unexecuted. This isolated one-shot service joins
the [independent issuer bootstrap](oidc-session-activation-release-proof-input-issuer-delivery.md),
actual recovery packet reader, [packet-derived producer](oidc-session-activation-release-proof-input-production.md)
and exact dynamic proof-worker staging. Source packaging is not installation,
resource observation, deployment or production acceptance.

## Fixed original owner

Root delivery authenticates launch, policy, completion bootstrap and signer
enrollment originals before the root signing key is read, then permanently
drops the same PID to UID/GID 65494. Startup consumes exactly these inherited
descriptors, keeping the original work/window and delivery guard:

| FD | Resource |
| --- | --- |
| 198 | Runtime root public key |
| 199 | Signed issuer launch bootstrap |
| 200 | Root-created public setup listener |
| 201 | Independent issuer policy |
| 202 | Independent consume-completion bootstrap |
| 203 | Proof signer enrollment |
| 204 | Intent signer enrollment |
| 205 | Root signing key, never a public-app resource |

The public listener is fixed at
`/run/catchplate/oidc-session-activation-release-proof-inputs/grants.sock` and
admits only kernel peer UID/GID 65532. The owner holds immutable configuration,
original descriptor identities, the exact listener, TLS identities and actual
`SuccessorExecutionRecoveryReader` configuration. It creates no new ledger,
construction clock, post-drop exec or caller-selected path/SQL/FD allowance.

The entrypoint's isolated issuer-local TLS mount supplies only `ca.pem`,
`custody.crt` and `custody.key` at the existing fixed completion TLS paths.
The private key is root:65494 mode 0440. No private history/delivery AES key,
completion writer key or proof signer enters this issuer. These paths and
signed pins must be independently provisioned and observed; documentation
does not create them or isolate a process from a hostile host root.

## One exchange and one private read

`initialize_from_environment(work=..., live_window=...,
transport_deadline_ns=..., delivery_current=...)` accepts the actual retained
delivery continuation. `require_started().serve_once()` spends its single-use
latch before readiness, accept or request bytes. The fixed raw4 request is:

`(purpose, signed_completion_request, state_receipt, signed_release_intent)`.

The caller supplies no packet, possession token, target or success DTO. The
actual independent policy's completion material supplies both `packet_digest`
and `current_pending`, and its custody configuration constructs the genuine
read-only recovery reader. A separate one-use read latch precedes the sole
bounded read. The returned packet is ordinary historical data until the
producer checks its exact independent identity and signed controls.

The reader receives the source-fixed `_resource_current` guard: original
resource identities, TLS, immutable reader configuration, all owned sockets,
PID, work and original lifetime stay checked while the real reader owns its
transient database connection. Full descriptor inventory is checked immediately
before and after that exact typed read. This is not a boolean inventory bypass,
an arbitrary descriptor exemption or a generic callback selected by callers.
The reader retains its own fixed configuration, role, TLS and query checks.

The actual producer receives request raw3 plus the separately read packet,
four independent originals and the root key pair. It derives and signs only
the exact proof bootstrap with embedded release custody. The service re-admits
that actual signed original and retains its narrower output/intent liveness
through staging, public send and normal close. Child guards use the original
resource guard, not a closure that recursively includes their own result.

## Exact staging before public response

The actual `_DeliveryChannel` owns one nonblocking CLOEXEC outgoing socket to
`/run/catchplate/oidc-session-activation-token-release/proof-bootstrap.sock`.
It accepts only the actual issuer owner, original work, narrowing deadline and
the exact `_IssuerOwner._current` bound method. The root peer is pinned before
any body bytes. Transport never closes or detaches the owner's socket.

Raw2 staging contains its fixed purpose and the exact produced bootstrap.
The returned `(b"staged", bootstrap_identity_ascii)` must name the independently
framed outgoing original, and normal socket closure must be established before
the service sends raw1 to the public caller. A matched staging ACK establishes
only the receiver's exact authenticated sealed-original/resource handoff,
**not worker readiness, a private proof, SQL execution or token release**.
The later proof worker still checks actual old-token possession and private
committed evidence; this service never receives that old token.

Explicit nested launch `/v2` adds the independently signed
`grantDeliveryEndpoint` at
`/run/catchplate/oidc-session-activation-token-release/grant-issuer-bootstrap.sock`.
Only after the worker ACK and normal close does the distinct source-owned
`_GrantDeliveryChannel` open its fixed third socket slot, pin root peer 0:0 and
stage the **same immutable bootstrap bytes** to the separate grant issuer. Its
own fixed purpose/codec and independently computed bootstrap identity must
match the second ACK, with normal close established before public raw1 reply.
The channel accepts only the actual issuer and `_IssuerOwner._current`, never
an arbitrary descriptor or resource-guard substitute. Full inventory remains
the inherited eight plus the actual public connection and the one currently
owned staging connection; the two outgoing connections never overlap.

Launch `/v1` remains worker-only and rejects the extra endpoint. V2 latches each
destination once under the same original work/window and narrowing deadline.
If the second stage is uncertain after the first was acknowledged, no rollback,
repeat of either stage, replacement allowance or public success reply follows.
Neither ACK establishes receiver service readiness or a completed release.

## Bounds and terminal cleanup

The owner measures actual delivered and second-admission originals/graphs and
reserves root/key/TLS and fixed request/response/staging/ACK capacity under the
unchanged 64 MiB whole-inventory ceiling. It rejects excessive cold inventory
before reading bodies, tightens the public request cap before allocation, and
passes an eightfold remaining packet reservation to the reader before row-byte
allocation. The producer receives the remaining aggregate allowance through
`maximum_original_bytes`, applied to initial decoding and its existing exact
wrapped-output/readback reservation before signing or wrapper allocation.
Output admission/staging have their own conservative eightfold readback bound.
Only v2 adds the second fixed header/purpose/ACK reservation; both destinations
reuse the already admitted original, without a second sender-side decoding.
These are tightening capacity checks, not renewed authority or time.

There is one request, one read, one production and one attempt per required
staging destination. Missing
responses, failed guards, partial publication or indeterminate cleanup are
terminal; no status/error reply or reconnect/retry follows. Cleanup checks
actual object/descriptor identity, closes each owned socket and inherited
resource once, and preserves uncertainty across repeated `close()` calls.
The finite runner returns success only after the real exchange and established
cleanup. Request/packet/root-key bytes are not journaled or logged.

This sender does not supply the grant receiver's independent policy or turn a
proof bootstrap into issuance authority. The separate dynamic receiver must
authenticate its own original policy and the incoming bootstrap before sealing
resources and acknowledging it; the old static grant profile is unchanged.
This connection does not complete public activation. Actual resources and
provisioning/deployment, public HTTP/current-auth/cookie completion, recovery
and portal work remain separate open boundaries.
