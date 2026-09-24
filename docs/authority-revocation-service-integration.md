# Private revocation service integration

## Status

Source `.51` adds real, importable raw transport helpers and a configured
issuer factory. These components are **unbuilt and unexecuted**. They are not
an enabled serving route: `AuthorityServer._serve_connection`, the public
`AuthorityProcess.handle` purpose gates and the transition registry remain
unchanged. No socket exchange, measured launch, PostgreSQL admission or
committed issuance has been verified for this source.

Source `.55` adds a private configured verifier method for the
[authenticated planner handoff](authority-revocation-handoff.md#configured-verifier-ownership).
It owns caller inputs and full measured configuration before guarded launch
callbacks, checks configuration/key/policy bindings, and invokes actual
original-byte replay. It does not enable a serving purpose or combine planner
and planner-writer credentials.

The [authenticated invocation](authority-revocation-invocation.md) and
[issuer custody](authority-revocation-issuance.md) contracts still apply.

## Original-byte transport

`authority_transport` owns the actual Unix peer-credential lookup, bounded
framing and raw request/response operations. It imports neither the active
service nor its registry. This lets isolated fixtures exercise real transport
code without bypassing the unfinished service registry.

The private successor receiver reads the eight-byte frame length and rejects
sizes outside 2 bytes through 4 MiB before reading the body. It returns opaque
original bytes, including invalid JSON, for the strict invocation verifier to
admit or reject. The sender checks the same request bound before opening a
socket, checks the configured peer UID/GID before sending, and bounds its raw
response to 4 MiB. Every post-open path closes the socket. Neither helper
interprets a response as an authorization grant.

Legacy service helpers delegate framing primitives but retain their existing
64 MiB ceiling and canonical JSON parser. The new byte path is separate;
calling a legacy helper does not establish strict pre-parse admission.

## Configured issuer construction

The actual service entry point loads root-signed measured configuration before
constructing `AuthorityProcess`. The private factory requires the issuer role,
the issuer process mode and the active issuer launch guard. It supplies the
existing measured payload/digest and the actual launch-generation context to
`_issuer_from_configuration_on_work`. Arbitrary dataclass or dictionary
construction is not equivalent to this admission chain.

The inert mapper owns the full payload and the seven launch bindings used by
measured configuration admission before key callbacks. It recomputes the
canonical configuration commitment, requires membership in the launch's
sorted unique configuration list, and joins generation, predecessor, rollback
floor and operation manifest. This successor requires a positive generation;
the general service's generation-zero behavior is not changed.

The issuer and verifier mappers share that exact pre-key capture/commitment
body. The issuer retains its original five-hash schedule; the verifier maps
only its own two public keys, identities and historical age/skew policy.

| Issuer setting | Configured source and check |
| --- | --- |
| Planner/verifier keys | Their respective role raw keys, checked against SPKI and response-signing pins |
| Witness key and identity | `replayWitness`, not the separate credential-release witness |
| Planner identity | Planner session, measurement and attestation pins; not planner-writer measurement |
| Verifier identity | Existing VerifierSession/v2 digest over configuration, verifier measurement and attestation |
| Issuer session | Existing CapabilityIssuerSession/v1 over database role, three TLS fields and three issuance pins; must match configuration |
| Current issuer pins | Issuer measurement, attestation and credential-issuance digest plus the age/skew policy below |
| Configuration/generation | Independently supplied measured digest and matched active-launch bindings |

The mapper does not verify a root signature or attest a process by itself.
Those admissions belong to the actual service load/launch chain. It also
cannot replace the real connector's database role, TLS, privilege or
transaction checks. No issuer capability-signing key is introduced; a launch
identity key is not used as a verifier signing key.

Configuration legitimately permits finite fractional timeouts. Its local
capture and prepaid canonical encoder preserve those exact values and the
service's JSON spelling, including negative zero. Nonfinite floats are denied.
The existing no-float generation/proof capture rules are unchanged.

## Policy and work ownership

The existing database verifier's 30-second maximum age and 5-second maximum
clock skew now have one shared source definition in `authority_contract`;
the database names remain aliases with unchanged values. The new issuer uses
the minimum of that maximum age and its measured `maximumInternalAgeNs`.
Consequently, construction cannot widen a stricter measured internal age.
Clock skew is source-pinned, never supplied by an invocation payload.

Configuration ownership, its canonical commitment, actual raw-key/SPKI work,
identity framing and comparisons use the caller's existing remaining work.
There are five hashes on the successful factory path: one configuration hash,
two SPKI hashes and two session hashes. Work consumed before construction is
not reset. Native key internals and socket framing are not represented as
JSON/hash work. Transport recorders do not establish live peer or deployment
admission.

`AuthorityProcess._issue_revocation_invocation_bytes` bounds original immutable
bytes, obtains this configured issuer and passes the same bytes/work directly
to `issue_authenticated`. No parsed-payload, successful-proof, caller DSN or
alternate opener can replace that private composition.

## Remaining production work

The helpers and private process method are callable components, not a complete
network handler. Enabling dispatch still requires coordinated original-byte
ingress, serving integration of the [independently observed planning path](authority-revocation-observed-planning.md)
and its [original-byte verifier handoff](authority-revocation-handoff.md),
durable original invocation retention, and the successor order: retain plan,
reserve execution, produce capability, sign/send invocation, issue capability.
Source `.62` supplies a private [measured writer action](authority-revocation-writer-action.md)
for atomic retain-and-reserve with independent inputs and same-configuration
policy binding. It is not connected to authenticated RPC or serving dispatch.
Source `.63` adds pure [detached writer commitments](authority-revocation-writer-commitment.md):
original verifier intent, planner relay and separate plan/context/history bodies.
Their signatures and byte commitments do not supply transport, durable custody,
an acknowledgment signer or permission to bypass the actual writer action.
Source `.64` adds the private [authenticated writer composition](authority-revocation-writer-composition.md):
five original byte strings, one held measured configuration and key tuple,
guarded current clocks, genuine authentication, historical-policy comparison
and actual atomic retention/reservation. Source `.65` adds immutable
[original-request custody](authority-revocation-writer-request-storage.md)
inside the same common savepoint, including exact retry comparison and both
real replays. It does not enable dispatch, provide signed acknowledgment
custody or implement detached-body transport.
Source `.66` separately loads a [writer-only response key](authority-revocation-writer-signer.md)
through the exact retained descriptor closure. Its dedicated slot cannot enable
the generic internal-envelope signer; no ACK creation or release is added.
Post-plan witness binding, current-root one-use execution and atomic terminal
publication remain incomplete. The four unfinished WebAuthn authority kernels
must not be bypassed to make the registry import or tests succeed.

The private combined coordinator needs planner read and writer persistence
credentials. Actual service-role admission separates those credentials, so
serving integration must preserve a distinct authenticated planner-writer RPC;
the combined owner is not a drop-in planner process implementation.

Immutable dependency/coverage approvals, sealed verification prerequisites
and independently operated production Nitro/KMS, signing and witness services
remain necessary. The implementation/source-freeze/single preparation and
sequential no-build verification workflow in [goal.md](../goal.md) is unchanged.
